use crate::mm::*;
use crate::util::UnsafeRef;
use crate::{mm::phys::*, util::SpinLock};
use core::{arch::asm, sync::atomic::AtomicBool};

use moto_sys::ErrorCode;

// The full physical memory is mapped to [DIRECT_MAP_OFFSET, *)
pub const PAGING_DIRECT_MAP_OFFSET: u64 = 1_u64 << 46;

pub const PAGE_SIZE_SMALL_LOG2: u8 = 12;
pub const PAGE_SIZE_MID_LOG2: u8 = 21;
pub const PAGE_SIZE_LARGE_LOG2: u8 = 30;

pub const PAGE_SIZE_SMALL: u64 = 1_u64 << PAGE_SIZE_SMALL_LOG2; // 4K
pub const PAGE_SIZE_MID: u64 = 1_u64 << PAGE_SIZE_MID_LOG2; // 2M
pub const PAGE_SIZE_LARGE: u64 = 1_u64 << PAGE_SIZE_LARGE_LOG2; // 1G

fn kpt() -> PageTableImpl {
    let l4_table = kpt_phys_addr() + PAGING_DIRECT_MAP_OFFSET;

    PageTableImpl {
        table_l4: unsafe { (l4_table as *mut HwPageTable).as_mut().unwrap() },
        userspace: false,
        dead: false,
    }
}

pub fn virt_to_phys(virt_addr: u64) -> Option<u64> {
    kpt().virt_to_phys(virt_addr)
}

pub fn kpt_phys_addr() -> u64 {
    unsafe {
        let mut cr3: u64;
        asm!("mov rax, cr3", out("rax") cr3, options(nostack, nomem));
        cr3
    }
}

pub fn l3_direct_phys_table_phys_addr() -> u64 {
    let virt_addr = PAGING_DIRECT_MAP_OFFSET;
    let idx_l4 = PageTableImpl::idx_l4(virt_addr);
    let kpt = kpt();
    let pte_l4 = kpt.table_l4.get(idx_l4);

    assert!(pte_l4.is_present());

    let table_l3 = HwPageTable::from_pte(pte_l4);
    (table_l3 as *const _ as usize as u64) - PAGING_DIRECT_MAP_OFFSET
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
    const USER: u64 = 0b_0000_0100; // bit 2.
    const ACCESSED: u64 = 0b_0010_0000; // bit 5.
    const HUGE: u64 = 0b_1000_0000; // bit 7.
    const MMIO_RW: u64 = 0b_0011_1011; // bit 0: present; bit 1: writable;
                                       // bit 3: write through; bit 4: no cache; bit 5: accessed.

    const _PRESENT_WRITABLE_HUGE: u64 = 0b_1000_0111; // bit 0: present; bit 1: writable; bit 7: huge page.

    #[inline]
    const fn empty() -> Self {
        Self { entry: 0 }
    }

    fn from_u64(val: u64) -> Self {
        Self { entry: val }
    }

    fn is_empty(&self) -> bool {
        self.entry == 0
    }

    fn is_huge_page(&self) -> bool {
        (self.entry & Self::HUGE) != 0
    }

    fn is_present(&self) -> bool {
        (self.entry & Self::PRESENT) != 0
    }

    #[inline]
    fn get_addr(&self) -> u64 {
        self.entry & 0x_000f_ffff_ffff_f000
    }
}

/// A page table. Quite possible, in use by the CPU.
#[repr(align(4096))]
#[repr(C)]
struct HwPageTable {
    entries: [PTE; Self::PTE_COUNT],
}

impl HwPageTable {
    // The number of entries in a page table.
    const PTE_COUNT: usize = 512;

    #[inline]
    fn self_phys_addr(&self) -> u64 {
        let virt_addr = (self as *const Self) as usize as u64;
        assert!((virt_addr & PAGING_DIRECT_MAP_OFFSET) != 0);
        virt_addr ^ PAGING_DIRECT_MAP_OFFSET
    }

    fn set(&mut self, idx: u64, pte: PTE) {
        let idx = idx as usize;
        assert!(idx < Self::PTE_COUNT);
        self.entries[idx] = pte;
    }

    fn get(&self, idx: u64) -> PTE {
        let idx = idx as usize;
        assert!(idx < Self::PTE_COUNT);
        self.entries[idx]
    }

    fn from_pte(pte: PTE) -> &'static mut Self {
        let phys_addr = pte.entry & 0x_000f_ffff_ffff_f000;
        assert_eq!(0, phys_addr & PAGING_DIRECT_MAP_OFFSET);
        let virt_addr = phys_addr | PAGING_DIRECT_MAP_OFFSET;
        assert!(virt_addr != 0);
        unsafe { &mut *(virt_addr as *mut HwPageTable) }
    }

    fn is_empty(&self) -> bool {
        for entry in &self.entries {
            if !entry.is_empty() {
                return false;
            }
        }
        true
    }

    fn _current() -> &'static mut HwPageTable {
        unsafe {
            let value: u64;
            core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));

            let addr = value & 0x_000f_ffff_ffff_f000;
            &mut *(addr as *mut HwPageTable)
        }
    }

    fn get_or_create(&mut self, idx: u64, pde_flags: u64) -> &'static mut Self {
        let pte = self.get(idx);
        if !pte.is_empty() {
            assert!(!pte.is_huge_page());
            return Self::from_pte(pte);
        }

        let frame = phys_allocate_frameless(PageType::SmallPage).unwrap();
        zero_page(frame + PAGING_DIRECT_MAP_OFFSET, PageType::SmallPage);

        let pte = PTE::from_u64(frame | pde_flags);
        self.entries[idx as usize] = pte;

        Self::from_pte(pte)
    }

    fn alloc() -> Result<&'static mut Self, ErrorCode> {
        let frame = phys_allocate_frameless(PageType::SmallPage)?;
        zero_page(frame + PAGING_DIRECT_MAP_OFFSET, PageType::SmallPage);
        Ok(Self::from_pte(PTE::from_u64(frame)))
    }

    fn dealloc(&self) {
        assert!(self.is_empty());
        phys_deallocate_frameless(self.self_phys_addr(), PageType::SmallPage);
    }
}

struct PageTableImpl {
    table_l4: &'static mut HwPageTable,
    userspace: bool,
    dead: bool,
}

impl PageTableImpl {
    fn virt_to_phys(&self, virt_addr: u64) -> Option<u64> {
        let idx_l4 = PageTableImpl::idx_l4(virt_addr);
        let pte_l4 = self.table_l4.get(idx_l4);

        if pte_l4.is_empty() || !pte_l4.is_present() {
            return None;
        }

        let table_l3 = HwPageTable::from_pte(pte_l4);
        let idx_l3 = PageTableImpl::idx_l3(virt_addr);
        let pte_l3 = table_l3.get(idx_l3);
        if pte_l3.is_empty() || !pte_l4.is_present() {
            return None;
        }
        if pte_l3.is_huge_page() {
            if pte_l3.is_present() {
                return Some(pte_l3.get_addr() + (virt_addr & (PAGE_SIZE_LARGE - 1)));
            } else {
                return None;
            }
        }

        let table_l2 = HwPageTable::from_pte(pte_l3);
        let idx_l2 = PageTableImpl::idx_l2(virt_addr);
        let pte_l2 = table_l2.get(idx_l2);
        if pte_l2.is_empty() || !pte_l4.is_present() {
            return None;
        }
        if pte_l2.is_huge_page() {
            if pte_l2.is_present() {
                return Some(pte_l2.get_addr() + (virt_addr & (PAGE_SIZE_MID - 1)));
            } else {
                return None;
            }
        }

        let table_l1 = HwPageTable::from_pte(pte_l2);
        let idx_l1 = PageTableImpl::idx_l1(virt_addr);
        let pte_l1 = table_l1.get(idx_l1);
        if pte_l1.is_present() {
            Some(pte_l1.get_addr() + (virt_addr & (PAGE_SIZE_SMALL - 1)))
        } else {
            None
        }
    }

    const fn idx_l4(virt_addr: u64) -> u64 {
        (virt_addr >> 39) & 0o777 // 39 == (12 + 9 + 9 + 9)
    }

    const fn idx_l3(virt_addr: u64) -> u64 {
        (virt_addr >> 30) & 0o777 // 30 == (12 + 9 + 9)
    }

    const fn idx_l2(virt_addr: u64) -> u64 {
        (virt_addr >> 21) & 0o777 // 21 == (12 + 9)
    }

    const fn idx_l1(virt_addr: u64) -> u64 {
        (virt_addr >> 12) & 0o777
    }

    fn get_kernel_pte(&self, vmem_addr: u64) -> PTE {
        let idx_l4 = Self::idx_l4(vmem_addr);
        self.table_l4.get(idx_l4)
    }

    fn insert_kernel_pte(&mut self, pte: PTE, vmem_addr: u64) {
        let idx_l4 = Self::idx_l4(vmem_addr);
        assert!(self.table_l4.get(idx_l4).is_empty());
        self.table_l4.set(idx_l4, pte);
    }

    fn remove_kernel_pte(&mut self, vmem_addr: u64) {
        let idx_l4 = Self::idx_l4(vmem_addr);
        assert!(!self.table_l4.get(idx_l4).is_empty());
        self.table_l4.set(idx_l4, PTE::empty());
    }

    fn map_page(&mut self, phys_addr: u64, virt_addr: u64, kind: PageType, pte_flags: u64) {
        assert_eq!(0, phys_addr & (kind.page_size() - 1));
        assert_eq!(0, virt_addr & (kind.page_size() - 1));

        let page_directory_flags = if (pte_flags & PTE::USER) != 0 {
            // TODO: maybe this is too permissive?
            PTE::PRESENT | PTE::WRITABLE | PTE::USER | PTE::ACCESSED
        } else {
            PTE::PRESENT | PTE::WRITABLE | PTE::ACCESSED
        };

        let idx_l4 = PageTableImpl::idx_l4(virt_addr);
        let table_l3 = self.table_l4.get_or_create(idx_l4, page_directory_flags);

        let idx_l3 = PageTableImpl::idx_l3(virt_addr);
        if kind == PageType::LargePage {
            assert!(table_l3.get(idx_l3).is_empty());
            let pte = PTE::from_u64(phys_addr | pte_flags);
            table_l3.set(idx_l3, pte);
            return;
        }

        let table_l2 = table_l3.get_or_create(idx_l3, page_directory_flags);

        let idx_l2 = PageTableImpl::idx_l2(virt_addr);
        if kind == PageType::MidPage {
            assert!(table_l2.get(idx_l2).is_empty());
            let pte = PTE::from_u64(phys_addr | pte_flags);
            table_l2.set(idx_l2, pte);
            return;
        }

        assert_eq!(kind, PageType::SmallPage);
        let table_l1 = table_l2.get_or_create(idx_l2, page_directory_flags);

        let idx_l1 = PageTableImpl::idx_l1(virt_addr);

        {
            // remove this block
            if !table_l1.get(idx_l1).is_empty() {
                log::error!("map 0x:{:x}: already there.", virt_addr);
            }
        }
        assert!(table_l1.get(idx_l1).is_empty());
        let pte = PTE::from_u64(phys_addr | pte_flags);
        table_l1.set(idx_l1, pte);
    }

    fn unmap_page(&mut self, phys_addr: u64, virt_addr: u64, kind: PageType) {
        assert_eq!(0, phys_addr & (kind.page_size() - 1));
        assert_eq!(0, virt_addr & (kind.page_size() - 1));

        let idx_l4 = PageTableImpl::idx_l4(virt_addr);
        let pte_l4 = self.table_l4.get(idx_l4);
        assert!(!pte_l4.is_empty());

        let table_l3 = HwPageTable::from_pte(pte_l4);

        let idx_l3 = PageTableImpl::idx_l3(virt_addr);
        let pte_l3 = table_l3.get(idx_l3);
        assert!(!pte_l3.is_empty());
        if kind == PageType::LargePage {
            assert!(pte_l3.is_huge_page());
            table_l3.set(idx_l3, PTE::empty());
            if table_l3.is_empty() {
                self.table_l4.set(idx_l4, PTE::empty());
                phys_deallocate_frameless(table_l3.self_phys_addr(), PageType::SmallPage);
            }
            self.flush_virt_addr(virt_addr);
            return;
        }

        assert!(!pte_l3.is_huge_page());
        let table_l2 = HwPageTable::from_pte(pte_l3);

        let idx_l2 = PageTableImpl::idx_l2(virt_addr);
        let pte_l2 = table_l2.get(idx_l2);
        assert!(!pte_l2.is_empty());
        if kind == PageType::MidPage {
            assert!(pte_l2.is_huge_page());
            table_l2.set(idx_l2, PTE::empty());
            if table_l2.is_empty() {
                table_l3.set(idx_l3, PTE::empty());
                phys_deallocate_frameless(table_l2.self_phys_addr(), PageType::SmallPage);
                if table_l3.is_empty() {
                    self.table_l4.set(idx_l4, PTE::empty());
                    phys_deallocate_frameless(table_l3.self_phys_addr(), PageType::SmallPage);
                }
            }
            self.flush_virt_addr(virt_addr);
            return;
        }

        assert!(!pte_l2.is_huge_page());
        assert_eq!(kind, PageType::SmallPage);
        let table_l1 = HwPageTable::from_pte(pte_l2);

        let idx_l1 = PageTableImpl::idx_l1(virt_addr);
        assert!(!table_l1.get(idx_l1).is_empty());
        table_l1.set(idx_l1, PTE::empty());
        if table_l1.is_empty() {
            table_l2.set(idx_l2, PTE::empty());
            phys_deallocate_frameless(table_l1.self_phys_addr(), PageType::SmallPage);
            if table_l2.is_empty() {
                table_l3.set(idx_l3, PTE::empty());
                phys_deallocate_frameless(table_l2.self_phys_addr(), PageType::SmallPage);
                if table_l3.is_empty() {
                    self.table_l4.set(idx_l4, PTE::empty());
                    phys_deallocate_frameless(table_l3.self_phys_addr(), PageType::SmallPage);
                }
            }
        }
        self.flush_virt_addr(virt_addr);
    }

    fn is_readable(&self, virt_addr: u64) -> bool {
        let idx_l4 = PageTableImpl::idx_l4(virt_addr);
        let pte_l4 = self.table_l4.get(idx_l4);

        if pte_l4.is_empty() || !pte_l4.is_present() {
            return false;
        }

        let table_l3 = HwPageTable::from_pte(pte_l4);
        let idx_l3 = PageTableImpl::idx_l3(virt_addr);
        let pte_l3 = table_l3.get(idx_l3);
        if pte_l3.is_empty() || !pte_l4.is_present() {
            return false;
        }
        if pte_l3.is_huge_page() {
            return pte_l3.is_present();
        }

        let table_l2 = HwPageTable::from_pte(pte_l3);
        let idx_l2 = PageTableImpl::idx_l2(virt_addr);
        let pte_l2 = table_l2.get(idx_l2);
        if pte_l2.is_empty() || !pte_l4.is_present() {
            return false;
        }
        if pte_l2.is_huge_page() {
            return pte_l2.is_present();
        }

        let table_l1 = HwPageTable::from_pte(pte_l2);
        let idx_l1 = PageTableImpl::idx_l1(virt_addr);
        let pte_l1 = table_l1.get(idx_l1);
        pte_l1.is_present()
    }

    fn flush_virt_addr(&self, virt_addr: u64) {
        if self.dead {
            // This is a userspace PT and the process is dead: no need to flush TLB.
            return;
        }
        super::tlb::invalidate(self.table_l4.self_phys_addr(), virt_addr, 1);
        // invalidate(self.table_l4.self_phys_addr(), virt_addr, 1);
    }
}

pub fn flush_kpt() {
    unsafe {
        asm!(
            "mov rax, cr3",
            "mov cr3, rax",
            out("rax") _,
            options(nostack)
        )
    }
}

// Called from IRQ.
pub fn invalidate(page_table: u64, first_page_vaddr: u64, num_pages: u64) {
    let mut current_page_table: u64;
    unsafe {
        asm!(
            "mov rax, cr3",
            out("rax") current_page_table,
            options(nostack)
        )
    }

    if current_page_table != page_table {
        return;
    }

    let mut vaddr = first_page_vaddr;
    for _ in 0..num_pages {
        unsafe {
            asm!(
                "invlpg [{}]",
                in(reg) vaddr,
                options(nostack, preserves_flags)
            );
        }
        vaddr += PAGE_SIZE_SMALL;
    }
}

pub fn init_paging_bsp() {
    // Unmap everything below kernel's offset.
    let idx_l4_kernel = PageTableImpl::idx_l4(crate::mm::virt::kernel_vmem_offset());
    debug_assert_ne!(idx_l4_kernel, 0);

    let kpt = kpt();
    let table_l4 = kpt.table_l4;

    table_l4.set(0, PTE::empty());

    crate::util::full_fence();
    flush_kpt();
    crate::util::full_fence();
}

pub struct PageTable {
    // Use a raw pointer so that we can construct PageTable around the kernel page table,
    // which is static. In addition, PageTable, as part of AddressSpace, should be Send/Sync.
    inst: UnsafeRef<SpinLock<PageTableImpl>>,
}

impl Drop for PageTable {
    fn drop(&mut self) {
        unsafe {
            use alloc::boxed::Box;
            {
                let guard = self.inst.get().lock(1);
                assert!(guard.userspace);
                guard.table_l4.dealloc();
            }

            // Trigger the drop.
            let _foo = Box::from_raw(self.inst.get_mut() as *mut SpinLock<PageTableImpl>);
        }
    }
}

impl PageTable {
    pub fn phys_addr(&self) -> u64 {
        unsafe { self.inst.get().lock(2).table_l4.self_phys_addr() }
    }

    pub fn new_kernel_page_table() -> Self {
        static CREATED: AtomicBool = AtomicBool::new(false);
        assert!(!CREATED.swap(true, core::sync::atomic::Ordering::AcqRel));

        let l4_table = unsafe {
            ((kpt_phys_addr() + PAGING_DIRECT_MAP_OFFSET) as *mut HwPageTable)
                .as_mut()
                .unwrap()
        };

        #[cfg(debug_assertions)]
        crate::raw_log!("kernel page table: 0x{:x}", l4_table as *const _ as usize);

        use alloc::boxed::Box;
        let kpt = Box::leak(Box::new(SpinLock::new(PageTableImpl {
            table_l4: l4_table,
            userspace: false,
            dead: false,
        })));

        PageTable {
            inst: UnsafeRef::from(kpt),
        }
    }

    pub fn new_user_page_table() -> Result<Self, ErrorCode> {
        use alloc::boxed::Box;

        let hw_page = HwPageTable::alloc()?;
        log::trace!("new user page table: 0x{:x}", hw_page as *const _ as usize);

        let inst = PageTableImpl {
            table_l4: hw_page,
            userspace: true,
            dead: false,
        };
        let inst = UnsafeRef::from_ptr(Box::leak(Box::new(SpinLock::new(inst))));

        Ok(PageTable { inst })
    }

    pub fn mark_dead(&self) {
        unsafe {
            debug_assert!(self.inst.get().lock(line!()).userspace);
            self.inst.get().lock(line!()).dead = true;
        }
    }

    pub fn map_page(
        &self,
        phys_addr: u64,
        virt_addr: u64,
        kind: PageType,
        options: MappingOptions,
    ) {
        let mut options = options;
        let dont_zero =
            options.contains(MappingOptions::DONT_ZERO) || options.contains(MappingOptions::MMIO);
        if dont_zero {
            options.remove(MappingOptions::DONT_ZERO);
        }

        let user = options.contains(MappingOptions::USER_ACCESSIBLE);
        if user {
            options.remove(MappingOptions::USER_ACCESSIBLE);
        }

        // Can we use a match expression below? The complier treats "ORs" as matching ORs, not
        // matching to ORed bitflags (i.e. matches single bits only).
        let mut pte_flags = if options == (MappingOptions::READABLE | MappingOptions::WRITABLE) {
            PTE::PRESENT | PTE::WRITABLE | PTE::ACCESSED
        } else if options
            == (MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::MMIO)
        {
            //            assert_eq!(kind, PageType::SmallPage);
            PTE::MMIO_RW
        } else if options == (MappingOptions::READABLE) {
            PTE::PRESENT | PTE::ACCESSED
        } else {
            todo!(
                "mapping options not implemented: 0x{:x} 0x{:x} {:?}",
                phys_addr,
                virt_addr,
                options
            )
        };

        if user {
            pte_flags |= PTE::USER;
        }

        if kind != PageType::SmallPage {
            pte_flags |= PTE::HUGE;
        }

        unsafe {
            self.inst
                .get()
                .lock(3)
                .map_page(phys_addr, virt_addr, kind, pte_flags);
        }

        if !dont_zero {
            zero_page(phys_addr + PAGING_DIRECT_MAP_OFFSET, kind);
        }
    }

    pub fn unmap_page(&self, phys_addr: u64, virt_addr: u64, kind: PageType) {
        unsafe {
            self.inst
                .get()
                .lock(4)
                .unmap_page(phys_addr, virt_addr, kind);
        }
    }

    pub fn is_readable(&self, virt_addr: u64) -> bool {
        unsafe { self.inst.get().lock(5).is_readable(virt_addr) }
    }

    pub fn map_kernel_to_user(&mut self, kpt: &PageTable) {
        let pte = unsafe {
            kpt.inst
                .get()
                .lock(6)
                .get_kernel_pte(crate::mm::virt::kernel_vmem_offset())
        };
        unsafe {
            self.inst
                .get()
                .lock(7)
                .insert_kernel_pte(pte, crate::mm::virt::kernel_vmem_offset())
        };
        let pte = unsafe {
            kpt.inst
                .get()
                .lock(8)
                .get_kernel_pte(crate::mm::PAGING_DIRECT_MAP_OFFSET)
        };
        unsafe {
            self.inst
                .get()
                .lock(line!())
                .insert_kernel_pte(pte, crate::mm::PAGING_DIRECT_MAP_OFFSET)
        };
    }

    pub fn unmap_kernel_from_user(&mut self) {
        unsafe {
            self.inst
                .get()
                .lock(line!())
                .remove_kernel_pte(crate::mm::virt::kernel_vmem_offset())
        };
        unsafe {
            self.inst
                .get()
                .lock(line!())
                .remove_kernel_pte(crate::mm::PAGING_DIRECT_MAP_OFFSET)
        };
    }

    pub fn virt_to_phys(&self, virt_addr: u64) -> Option<u64> {
        unsafe { self.inst.get().lock(line!()).virt_to_phys(virt_addr) }
    }
}
