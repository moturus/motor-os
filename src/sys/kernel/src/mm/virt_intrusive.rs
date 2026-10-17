// This module contains data structures used in virtual memory management that
// utilize intrusive collections: using normal vectors/maps is not right, as
// they involve heap allocations, and we don't want to do heap allocations
// while allocating virtual memory, as it results in nasty recursion.
use core::mem::MaybeUninit;

use intrusive_collections::{intrusive_adapter, Bound, UnsafeRef};
use intrusive_collections::{KeyAdapter, RBTree, RBTreeLink};
use intrusive_collections::{SinglyLinkedList, SinglyLinkedListLink};
use moto_sys::ErrorCode;

use crate::mm::{PageType, PAGE_SIZE_MID, PAGE_SIZE_SMALL_LOG2};
use crate::util::SpinLock;
use core::sync::atomic::Ordering;

use super::phys::Frame;
use super::slab::SlabArc;
use super::user_copy::UserCopyError;
use super::virt::VaddrMapStatus;
use super::{MappingOptions, MemorySegment, PAGE_SIZE_SMALL};

#[derive(Default)]
pub(super) struct Page {
    list_link: SinglyLinkedListLink,
    tree_link: RBTreeLink,
    start: u64,
    frame: SlabArc<Frame>,

    // If mapping_options & PRIVATE:
    // - frame is always not null;
    // - start points to the start of the page that holds pages for the allocator;
    // - this is the first struct page in the 4096 bytes given to page allocator.
    mapping_options: MappingOptions,
}

#[cfg(debug_assertions)]
impl Drop for Page {
    fn drop(&mut self) {
        assert!(self.is_empty())
    }
}

const STRUCT_PAGE_SZ: usize = core::mem::size_of::<Page>();
const _STRUCT_PAGE_SZ: () = assert!(core::mem::size_of::<Page>() == 72);
// struct Page is the largest per-page metadata admission must cover; see
// mm::admission::METADATA_BYTES_PER_PAGE. Pages are packed into small pages, so
// each costs PAGE_SIZE_SMALL / STRUCT_PAGES_IN_SMALL_PAGE of that budget; the
// rest goes to struct Frame (see phys) and page tables.
const _STRUCT_PAGE_FITS_ADMISSION: () = assert!(
    (PAGE_SIZE_SMALL as usize / STRUCT_PAGES_IN_SMALL_PAGE)
        <= (super::admission::METADATA_BYTES_PER_PAGE * 5 / 8)
);

const STRUCT_PAGES_IN_SMALL_PAGE: usize = PAGE_SIZE_SMALL as usize / STRUCT_PAGE_SZ; // == 56.
const _STRUCT_PAGES_IN_SMALL_PAGE: () = assert!(STRUCT_PAGES_IN_SMALL_PAGE == 56);

impl Page {
    fn clear(&mut self) {
        assert!(self.frame.is_null());
        assert!(!self.tree_link.is_linked());
        assert!(!self.list_link.is_linked());

        self.start = 0;
        self.mapping_options = MappingOptions::empty();
    }

    fn is_empty(&self) -> bool {
        self.start == 0
            && self.mapping_options.is_empty()
            && self.frame.is_null()
            && !self.list_link.is_linked()
            && !self.tree_link.is_linked()
    }

    // A page's kind is its frame's; an unbacked page (lazy, guard, reserved)
    // is small. The frame is the only record of it, so nothing can disagree.
    fn kind(&self) -> PageType {
        self.frame.get().map_or(PageType::SmallPage, Frame::kind)
    }

    fn size(&self) -> u64 {
        self.kind().page_size()
    }

    fn contains(&self, vmem_addr: u64) -> bool {
        (self.start <= vmem_addr) && (vmem_addr < (self.start + self.size()))
    }
}

// Per-page options for page `idx` of `num_pages`: guard ends are unmapped
// and the interior loses GUARD and LAZY; the segment's creation policy is
// never a hardware mapping option.
pub(super) fn page_mapping_options(
    segment_options: MappingOptions,
    idx: u64,
    num_pages: u64,
) -> MappingOptions {
    let options = segment_options.difference(MappingOptions::HUGE_ELIGIBLE);
    if !options.contains(MappingOptions::GUARD) {
        options
    } else if idx == 0 || idx == num_pages - 1 {
        MappingOptions::empty()
    } else {
        options.difference(MappingOptions::GUARD | MappingOptions::LAZY)
    }
}

intrusive_adapter!(PageListAdapter = UnsafeRef<Page>: Page { list_link: SinglyLinkedListLink });
intrusive_adapter!(PageTreeAdapter = UnsafeRef<Page>: Page { tree_link: RBTreeLink });

type PageSlab = [Page; STRUCT_PAGES_IN_SMALL_PAGE];

impl<'a> KeyAdapter<'a> for PageTreeAdapter {
    type Key = u64;

    fn get_key(&self, page: &'a Page) -> u64 {
        page.start
    }
}

#[derive(Default)]
struct PageAllocatorInner {
    free_list: SinglyLinkedList<PageListAdapter>, // Pages to use.
    slab_list: SinglyLinkedList<PageListAdapter>, // Slabs that hold the pages.
    free_page_count: u64,
    used_page_count: u64,
    slab_count: u64,
}

impl Drop for PageAllocatorInner {
    fn drop(&mut self) {
        assert!(self.is_empty());
    }
}

impl PageAllocatorInner {
    fn is_empty(&self) -> bool {
        self.free_list.is_empty()
            && self.slab_list.is_empty()
            && self.free_page_count == 0
            && self.used_page_count == 0
            && self.slab_count == 0
    }

    fn clear(&mut self) {
        assert_eq!(0, self.used_page_count);

        self.free_list.clear();
        self.free_page_count = 0;

        while let Some(page_ref) = self.slab_list.pop_front() {
            let page = unsafe { UnsafeRef::into_raw(page_ref).as_mut().unwrap() };
            let frame = page.frame.take();
            assert!(!page.list_link.is_linked()); // TODO: remove.
            page.clear();
            // Slab frames are not mapped explictly, we use PAGING_DIRECT_MAP_OFFSET,
            // so we don't do any explicit unmapping.
            core::mem::drop(frame); // Will deallocate the frame.
            self.slab_count -= 1;
        }

        assert!(self.is_empty())
    }

    fn alloc_page(&mut self) -> *mut Page {
        if self.free_list.is_empty() {
            debug_assert_eq!(0, self.free_page_count);

            self.alloc_slab();
        }

        let page = self.free_list.pop_front().unwrap();
        debug_assert!(page.is_empty());
        self.free_page_count -= 1;
        self.used_page_count += 1;

        UnsafeRef::into_raw(page)
    }

    fn free_page(&mut self, page: *mut Page) {
        #[cfg(debug_assertions)]
        assert!(unsafe { page.as_ref().unwrap().is_empty() });

        self.free_list
            .push_front(unsafe { UnsafeRef::from_raw(page) });
        self.free_page_count += 1;
        self.used_page_count -= 1;
    }

    fn alloc_slab(&mut self) {
        // Allocate a page. Note that we don't need to map the frame/page here,
        // as all phys mem has been mapped at PAGING_DIRECT_MAP_OFFSET.
        let frame = super::phys::allocate_frame(super::PageType::SmallPage);
        let virt_addr = frame.get().unwrap().start() + super::PAGING_DIRECT_MAP_OFFSET;

        // Initialize pages to default.
        let default_page = Page::default();
        let mut addr = virt_addr as usize;
        for _idx in 0..STRUCT_PAGES_IN_SMALL_PAGE {
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    &default_page as *const Page,
                    addr as *mut Page,
                    1,
                );
            }
            addr += STRUCT_PAGE_SZ;
        }

        // Get a proper array.
        let mut page_array = MaybeUninit::<&mut PageSlab>::uninit();
        page_array.write(unsafe { (virt_addr as usize as *mut PageSlab).as_mut().unwrap() });
        let page_array = unsafe { page_array.assume_init() };

        // Initialize the first page.
        let slab_page = &mut page_array[0];
        debug_assert!(slab_page.is_empty());

        slab_page.start = virt_addr;
        slab_page.frame = frame;
        slab_page.mapping_options = MappingOptions::PRIVATE;
        self.slab_list
            .push_front(unsafe { UnsafeRef::from_raw(slab_page as *const Page) });
        self.slab_count += 1;

        // Initialize the rest.
        for page in &mut page_array[1..] {
            debug_assert!(page.is_empty());

            self.free_list
                .push_front(unsafe { UnsafeRef::from_raw(page as *const Page) });
            self.free_page_count += 1;
        }
    }
}

#[derive(Default)]
pub(super) struct PageAllocator {
    inner: SpinLock<PageAllocatorInner>,
}

impl PageAllocator {
    fn alloc_page(&self) -> *mut Page {
        self.inner.lock(line!()).alloc_page()
    }

    fn free_page(&self, page: *mut Page) {
        self.inner.lock(line!()).free_page(page)
    }

    pub(super) fn clear(&self) {
        self.inner.lock(line!()).clear()
    }

    // The descriptors in use, for the self-tests.
    #[cfg(debug_assertions)]
    pub(super) fn used_pages(&self) -> u64 {
        self.inner.lock(line!()).used_page_count
    }
}

#[derive(Default)]
pub(super) struct VmemSegment {
    segment: super::MemorySegment,
    pages: RBTree<PageTreeAdapter>,
    owner: crate::util::UnsafeRef<super::virt::VmemRegion>,
    mapping_options: MappingOptions,
}

impl Drop for VmemSegment {
    fn drop(&mut self) {
        debug_assert!(self.is_empty());
    }
}

impl VmemSegment {
    pub(super) fn new(
        segment: MemorySegment,
        owner: &super::virt::VmemRegion,
        mapping_options: MappingOptions,
    ) -> Self {
        Self {
            segment,
            owner: crate::util::UnsafeRef::from(owner),
            mapping_options,
            pages: RBTree::new(PageTreeAdapter::new()),
        }
    }

    // Cleared or never set up. A live sparse segment may hold no pages, so
    // the tree alone says nothing.
    fn is_empty(&self) -> bool {
        self.segment.size == 0 && self.pages.is_empty()
    }

    pub(super) fn segment(&self) -> MemorySegment {
        self.segment
    }

    // The greatest page start not above the address, if its kind-sized
    // extent covers the address: interior addresses of a huge page resolve
    // to it, and gaps resolve to nothing.
    fn find_page(&self, vmem_addr: u64) -> Option<&Page> {
        let page = self.pages.upper_bound(Bound::Included(&vmem_addr)).get()?;
        page.contains(vmem_addr).then_some(page)
    }

    fn find_page_mut(&mut self, vmem_addr: u64) -> Option<&mut Page> {
        let page = self
            .pages
            .upper_bound(Bound::Included(&vmem_addr))
            .clone_pointer()
            .map(|ptr| unsafe { UnsafeRef::into_raw(ptr).as_mut().unwrap() })?;
        page.contains(vmem_addr).then_some(page)
    }

    pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
        assert!(self.segment.contains(vmem_addr));

        let Some(page) = self.find_page(vmem_addr) else {
            return VaddrMapStatus::Unmapped; // An untouched page of a sparse segment.
        };

        if let Some(frame) = page.frame.get() {
            if frame.is_mmio() {
                return VaddrMapStatus::Mmio;
            }
            let offset = vmem_addr - page.start;
            let phys_addr = frame.start() + offset;
            let refs = page.frame.refs();
            if refs == 1 {
                VaddrMapStatus::Private(phys_addr)
            } else {
                VaddrMapStatus::Shared(phys_addr)
            }
        } else {
            VaddrMapStatus::Unmapped
        }
    }

    pub(super) fn pin_user_page(
        &self,
        vmem_addr: u64,
        access: MappingOptions,
    ) -> Result<(SlabArc<Frame>, u64), UserCopyError> {
        let Some(page) = self.find_page(vmem_addr) else {
            // An untouched page of a sparse segment has the rights it would
            // be created with.
            if self
                .page_options_at(vmem_addr)
                .contains(access | MappingOptions::USER_ACCESSIBLE)
            {
                return Err(UserCopyError::PageAbsent(vmem_addr));
            }
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        };
        // Direct-map accesses bypass PTE protection; check the page's rights
        // while the caller holds the region lock, before acquiring the pin.
        if !page
            .mapping_options
            .contains(access | MappingOptions::USER_ACCESSIBLE)
        {
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        }
        let frame = page
            .frame
            .get()
            .ok_or(UserCopyError::PageAbsent(vmem_addr))?;
        if frame.is_mmio() {
            return Err(moto_rt::E_INVALID_ARGUMENT.into());
        }
        // The caller holds the region lock, so unmap cannot release the
        // mapping's last reference while this owning reference is acquired.
        Ok((page.frame.clone(), vmem_addr - page.start))
    }

    pub(super) fn unmap(mut self) -> u64 {
        // Note: it is important to unmap pages before freeing the segment
        // in the VMemRegion, otherwise a concurrent allocation may try
        // to map a page that is not yet unmapped.
        self.clear()
    }

    fn clear(&mut self) -> u64 {
        debug_assert_ne!(self.segment.size, 0);
        debug_assert!(!self.owner.is_null());

        // Unmap all mapped pages first, then do a single ranged TLB
        // shootdown: a shootdown IPIs all CPUs and spins for their acks,
        // so doing it per page makes large frees pathologically slow.
        let mut mapped_pages = 0_u64;
        for page in self.pages.iter() {
            if let Some(frame) = page.frame.get() {
                self.address_space().page_table.unmap_page_no_flush(
                    frame.start(),
                    page.start,
                    frame.kind(),
                );
                mapped_pages += 1;
            }
        }
        if mapped_pages > 0 {
            self.address_space().page_table.flush_pages(
                self.segment.start,
                self.segment.size >> PAGE_SIZE_SMALL_LOG2,
            );
        }

        let mut pages = self.pages.take();
        let mut cursor = pages.front_mut();
        while let Some(page) = cursor.remove() {
            let page_ptr = UnsafeRef::into_raw(page);
            let page_mut = unsafe { page_ptr.as_mut().unwrap() };
            // The frame is freed here, after the TLB flush above: no CPU can
            // reach a reused frame through a stale translation.
            page_mut.frame.take();
            page_mut.clear();
            self.address_space().page_allocator.free_page(page_ptr);
        }
        // The segment was accounted in full when it was reserved, whether
        // its pages were all created, touched later, or never touched.
        let sz = self.segment.size;

        self.segment = MemorySegment::empty_segment();
        self.owner.clear();

        sz
    }

    fn address_space(&self) -> &super::virt::AddressSpaceBase {
        unsafe { self.owner.get().address_space.get() }
    }

    pub(super) fn set_frame(&mut self, page: u64, frame: SlabArc<Frame>) {
        let page = self.find_page_mut(page).unwrap();
        debug_assert!(page.frame.is_null());
        page.frame = frame;
    }

    // Huge candidates of an eligible segment: its whole 2 MiB units. The
    // sizing rule already rounded the segment, so a tail is at most 1 MiB
    // and stays small.
    fn huge_candidates(&self) -> u64 {
        if self.mapping_options.contains(MappingOptions::HUGE_ELIGIBLE) {
            self.segment.size / PAGE_SIZE_MID
        } else {
            0
        }
    }

    pub(super) fn allocate_pages(&mut self) -> Result<(), ErrorCode> {
        assert!(self.segment.size > 0);
        assert!(self.pages.is_empty());

        if self.is_sparse() {
            // A page gets its descriptor with its frame: in the fault path,
            // or from the pager for a file-paged segment.
            debug_assert!(!self.mapping_options.contains(MappingOptions::HUGE_ELIGIBLE));
            return Ok(());
        }
        // Nothing is published yet, so a failed construction rolls the whole
        // segment back here, once; the caller then drops it.
        let result = self.construct();
        if result.is_err() {
            self.clear();
        }
        result
    }

    // Maps or reserves every page of the segment, in address order. Fails
    // only when the page table refuses the mapping options: it never fails
    // for lack of memory, admission keeps that away and exhaustion panics.
    fn construct(&mut self) -> Result<(), ErrorCode> {
        let num_pages = self.segment.size >> PAGE_SIZE_SMALL_LOG2;
        let huge = self.huge_candidates();
        let mut start = self.segment.start;
        // Huge pages come first in the address order, and after the first
        // refusal every remaining candidate is served small without asking.
        let mut refused = false;
        for _ in 0..huge {
            debug_assert_eq!(start & (PAGE_SIZE_MID - 1), 0);
            let options = page_mapping_options(self.mapping_options, 0, num_pages);
            let frame = if refused {
                None
            } else {
                super::phys::allocate_huge_frame()
                    .inspect_err(|_| refused = true)
                    .ok()
            };
            match frame {
                Some(frame) => {
                    self.map_frame(start, frame, options)?;
                    super::virt::HUGE_PAGES_MAPPED.fetch_add(1, Ordering::Relaxed);
                    start += PAGE_SIZE_MID;
                }
                None => {
                    super::virt::HUGE_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..(PAGE_SIZE_MID / PAGE_SIZE_SMALL) {
                        self.map_small(start, options)?;
                        start += PAGE_SIZE_SMALL;
                    }
                }
            }
        }
        let first_small = huge * (PAGE_SIZE_MID / PAGE_SIZE_SMALL);
        for idx in first_small..num_pages {
            self.map_small(
                start,
                page_mapping_options(self.mapping_options, idx, num_pages),
            )?;
            start += PAGE_SIZE_SMALL;
        }

        Ok(())
    }

    // One small page at `start`, mapped now unless the options leave it
    // unmapped: a reservation, a guard page.
    fn map_small(&mut self, start: u64, options: MappingOptions) -> Result<(), ErrorCode> {
        debug_assert!(!options.contains(MappingOptions::LAZY));
        if options.is_empty() {
            let page = self.new_page(start, options);
            self.pages.insert(unsafe { UnsafeRef::from_raw(page) });
            return Ok(());
        }
        let frame = super::phys::allocate_frame(PageType::SmallPage);
        self.map_frame(start, frame, options)
    }

    // A fresh descriptor for the page at `start`, not yet in the tree.
    fn new_page(&mut self, start: u64, options: MappingOptions) -> *mut Page {
        let page = self.address_space().page_allocator.alloc_page();
        let page_mut = unsafe { page.as_mut() }.unwrap();
        debug_assert!(page_mut.is_empty());
        page_mut.start = start;
        page_mut.mapping_options = options;
        page
    }

    // Map an owned frame of either kind at `start` and record it. The frame
    // is zeroed by the page table before its PTE is published. Fails only
    // when the page table refuses the mapping options; then the frame is
    // dropped and the segment is left as it was.
    fn map_frame(
        &mut self,
        start: u64,
        frame: SlabArc<Frame>,
        options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        let page = self.new_page(start, options);
        let page_mut = unsafe { page.as_mut() }.unwrap();
        let (phys, kind) = (frame.get().unwrap().start(), frame.get().unwrap().kind());
        if let Err(err) = self
            .address_space()
            .page_table
            .map_page(phys, start, kind, options)
        {
            page_mut.clear();
            self.address_space().page_allocator.free_page(page);
            return Err(err);
        }
        page_mut.frame = frame;
        self.pages.insert(unsafe { UnsafeRef::from_raw(page) });
        Ok(())
    }

    pub fn mmio_map(&mut self, phys_addr: u64, user: bool) -> Result<(), ErrorCode> {
        let start = self.segment.start;

        assert!(!self.pages.is_empty());
        let num_pages = self.segment.size >> PAGE_SIZE_SMALL_LOG2;

        let options = if user {
            MappingOptions::READABLE
                | MappingOptions::WRITABLE
                | MappingOptions::MMIO
                | MappingOptions::USER_ACCESSIBLE
        } else {
            MappingOptions::READABLE | MappingOptions::WRITABLE | MappingOptions::MMIO
        };

        let mut offset = 0;
        for _idx in 0..num_pages {
            let frame = super::phys::mmio_frame(phys_addr + offset)?;
            self.address_space().page_table.map_page(
                phys_addr + offset,
                start + offset,
                PageType::SmallPage,
                options,
            )?;
            let page = self.find_page_mut(start + offset).unwrap();
            debug_assert!(page.frame.is_null());
            page.frame = frame;
            page.mapping_options = options;
            offset += PAGE_SIZE_SMALL;
        }

        Ok(())
    }

    /// Installs a private copy of `source`, or a zeroed page with `None`.
    /// The region lock covers the absence check through installation, so
    /// overlapping fills never allocate twice against one page's commitment.
    pub(super) fn fill_file_page(
        &mut self,
        addr: u64,
        source: Option<&super::user::PinnedUserPage>,
    ) -> Result<bool, ErrorCode> {
        if !self.mapping_options.contains(MappingOptions::FILE_PAGED)
            || !addr.is_multiple_of(PAGE_SIZE_SMALL)
            || !self.segment.contains(addr)
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        if self.find_page(addr).is_some() {
            return Ok(false);
        }
        let mut options = self.mapping_options - MappingOptions::FILE_PAGED;
        let frame = super::phys::allocate_frame(PageType::SmallPage);
        if let Some(source) = source {
            let dst = frame.get().unwrap().start() + super::PAGING_DIRECT_MAP_OFFSET;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.kernel_addr() as *const u8,
                    dst as *mut u8,
                    PAGE_SIZE_SMALL as usize,
                );
            }
            options |= MappingOptions::DONT_ZERO;
        }
        self.map_frame(addr, frame, options)?;
        Ok(true)
    }

    pub(super) fn is_file_paged(&self) -> bool {
        self.mapping_options.contains(MappingOptions::FILE_PAGED)
    }

    // A sparse segment has descriptors only for the pages that got a frame.
    fn is_sparse(&self) -> bool {
        self.mapping_options
            .intersects(MappingOptions::LAZY | MappingOptions::FILE_PAGED)
    }

    // The options a page of this segment is created with: the per-page view
    // of the segment's, as construction derives it.
    fn page_options_at(&self, addr: u64) -> MappingOptions {
        let idx = (addr - self.segment.start) >> PAGE_SIZE_SMALL_LOG2;
        page_mapping_options(
            self.mapping_options,
            idx,
            self.segment.size >> PAGE_SIZE_SMALL_LOG2,
        )
    }

    // The page holding `addr`, created without a frame if the sparse
    // segment has none there yet.
    fn find_or_create_page(&mut self, addr: u64) -> &mut Page {
        if self.find_page(addr).is_none() {
            debug_assert!(self.is_sparse());
            let start = addr & !(PAGE_SIZE_SMALL - 1);
            let options = self.page_options_at(start);
            let page = self.new_page(start, options);
            self.pages.insert(unsafe { UnsafeRef::from_raw(page) });
        }
        self.find_page_mut(addr).unwrap()
    }

    pub(super) fn fix_pagefault(&mut self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        debug_assert!(self.segment.contains(pf_addr));

        // Note: this is run under spinlock on self.

        if self.mapping_options.contains(MappingOptions::FILE_PAGED) {
            // Only not-present faults are served: user (4), plus write (2)
            // where writable and instruction fetch (0x10) where executable.
            let code = error_code & !4;
            if error_code & 4 == 0
                || code & !(2 | 0x10) != 0
                || (code & 2 != 0 && !self.mapping_options.contains(MappingOptions::WRITABLE))
                || (code & 0x10 != 0 && !self.mapping_options.contains(MappingOptions::EXECUTABLE))
            {
                log::debug!("#PF: file-paged protection violation: 0x{error_code:x}");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            return if self.find_page(pf_addr).is_some() {
                Ok(()) // A fill raced with the fault.
            } else {
                Err(moto_rt::E_NOT_READY)
            };
        }

        if (((pf_addr & !(PAGE_SIZE_SMALL - 1)) == self.segment.start)
            || (pf_addr >= (self.segment.end() - PAGE_SIZE_SMALL)))
            && self.mapping_options.contains(MappingOptions::GUARD)
        {
            log::debug!("#PF: guard page");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        debug_assert_eq!(error_code & 4, 4);
        let error_code = error_code ^ 4;

        // Protection violations are never fixable: faults on present pages
        // (P, bit 0 — there are no CoW or other lazy-present mappings) and
        // instruction fetches (I/D, bit 4 — W^X: nothing executable is
        // lazily mapped). Without this check a fault on a present page
        // (e.g. an NX violation, or a write to rodata) would be "fixed" by
        // the concurrent-fault shortcut below and refault forever.
        if (error_code & (1 | 0x10)) != 0 {
            log::debug!("#PF: protection violation: 0x{:x}", error_code | 4);
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let page = self.find_or_create_page(pf_addr);
        debug_assert!(page.contains(pf_addr));

        if !page.frame.is_null() {
            // Multiple threads page-faulted the same address concurrently.
            let mapping_options = page.mapping_options;
            assert!(mapping_options.contains(MappingOptions::USER_ACCESSIBLE));
            assert!(!mapping_options.contains(MappingOptions::LAZY));
            assert!(!mapping_options.contains(MappingOptions::GUARD));
            return Ok(());
        }

        if error_code == 0 {
            // Read.
            if !page
                .mapping_options
                .contains(MappingOptions::USER_ACCESSIBLE)
            {
                log::debug!("#PF: not readable");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
        } else if error_code == 2 {
            // Write.
            if !page
                .mapping_options
                .contains(MappingOptions::USER_ACCESSIBLE)
                || !page.mapping_options.contains(MappingOptions::WRITABLE)
            {
                log::debug!("#PF: not writable");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
        } else {
            log::debug!("Unsupported #PF error code: 0x{:x}", error_code + 4);
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let lazy_options = page.mapping_options;
        page.frame = super::phys::allocate_frame(PageType::SmallPage);
        page.mapping_options.remove(MappingOptions::LAZY);
        page.mapping_options.remove(MappingOptions::GUARD);
        let mapping_options = page.mapping_options;

        let phys_addr = page.frame.get().unwrap().start();
        let virt_addr = page.start;
        let page_type = PageType::SmallPage;
        if let Err(err) = self.address_space().page_table.map_page(
            phys_addr,
            virt_addr,
            page_type,
            mapping_options,
        ) {
            // Roll back: a non-null frame with LAZY stripped but no PTE
            // installed would satisfy the concurrent-fault shortcut above,
            // so retries of the faulting access would refault forever.
            // Dropping the frame frees it.
            let page = self.find_page_mut(pf_addr).unwrap();
            page.frame = SlabArc::null();
            page.mapping_options = lazy_options;
            return Err(err);
        }
        // No TLB flush: the PTE went from non-present to present, and x86
        // CPUs don't cache non-present translations (and every unmap path
        // flushes), so no CPU — including this one — holds a stale entry.

        Ok(())
    }

    pub(super) fn share_with(
        &self,
        other: &mut Self,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        debug_assert_eq!(self.segment.size, other.segment.size);
        self.share_range_with(0, other, mapping_options)
    }

    /// Maps `other`'s size worth of this segment's pages, starting at page
    /// `first_page`, into `other`, sharing the frames. `other` is normally a
    /// reservation; pages it already maps are replaced. The whole range is
    /// checked first, so a refused share leaves `other` as it was.
    pub(super) fn share_range_with(
        &self,
        first_page: u64,
        other: &mut Self,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        let start = self.segment.start + (first_page << PAGE_SIZE_SMALL_LOG2);
        if start + other.segment.size > self.segment.end() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        // Segment provenance decides, whatever the actual backing: a huge
        // page must never reach the small-page replacement loop below, a
        // file-paged segment has no complete set of pages to share, and a
        // lazy destination may have no pages at all.
        if (self.mapping_options | other.mapping_options)
            .intersects(MappingOptions::HUGE_ELIGIBLE | MappingOptions::FILE_PAGED)
            || other.mapping_options.contains(MappingOptions::LAZY)
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        debug_assert!(!other.pages.is_empty());

        // The destination is dense, so its pages name every address of the
        // range. The source is walked in step with it, and a source page
        // that is not at the address the destination page names is a hole:
        // that, a page without a frame (lazy, guard) or MMIO at either end
        // refuses the share before anything changes.
        let other_start = other.segment.start;
        let source_addr = |dest_start: u64| start + (dest_start - other_start);
        let mut source = self.pages.find(&start);
        for dest in other.pages.iter() {
            let Some(frame) = source
                .get()
                .filter(|page| page.start == source_addr(dest.start))
                .and_then(|page| page.frame.get())
            else {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            };
            if frame.is_mmio() || dest.frame.get().is_some_and(Frame::is_mmio) {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            source.move_next();
        }

        let mut source = self.pages.find(&start);
        let mut other_cursor = other.pages.front();
        while let Some(that_page) = other_cursor
            .clone_pointer()
            .map(|ptr| unsafe { UnsafeRef::into_raw(ptr).as_mut().unwrap() })
        {
            let this_page = source.get().unwrap();
            debug_assert_eq!(this_page.start, source_addr(that_page.start));
            if !that_page.frame.is_null() {
                other.address_space().page_table.unmap_page(
                    that_page.frame.get().unwrap().start(),
                    that_page.start,
                    PageType::SmallPage,
                );
            }

            that_page.frame = this_page.frame.clone();
            other.address_space().page_table.map_page(
                this_page.frame.get().unwrap().start(),
                that_page.start,
                PageType::SmallPage,
                mapping_options,
            )?;
            that_page.mapping_options = mapping_options;
            source.move_next();
            other_cursor.move_next();
        }

        Ok(())
    }
}

// ----------------------- Segment Map ----------------------------- //

#[derive(Default)]
pub(super) struct SegmentNode {
    free_list_link: SinglyLinkedListLink,
    tree_link: RBTreeLink,
    vmem_segment: VmemSegment,
}

impl SegmentNode {
    pub(super) fn vmem_segment(&self) -> &VmemSegment {
        &self.vmem_segment
    }

    unsafe fn vmem_segment_mut<'a>(&self) -> &'a mut VmemSegment {
        let ptr = &self.vmem_segment as *const VmemSegment as usize as *mut VmemSegment;
        unsafe { ptr.as_mut().unwrap() }
    }

    fn is_empty(&self) -> bool {
        !self.free_list_link.is_linked()
            && !self.tree_link.is_linked()
            && self.vmem_segment.is_empty()
    }
}

const SEGMENT_NODE_SZ: usize = core::mem::size_of::<SegmentNode>();
const _SEGMENT_NODE_SZ: () = assert!(core::mem::size_of::<SegmentNode>() == 72);

const SEGMENT_NODES_IN_SMALL_PAGE: usize =
    ((PAGE_SIZE_SMALL as usize) - STRUCT_PAGE_SZ) / SEGMENT_NODE_SZ; // == 55.
const _SEGMENT_NODES_IN_SMALL_PAGE: () = assert!(SEGMENT_NODES_IN_SMALL_PAGE == 55);

intrusive_adapter!(SegmentListAdapter = UnsafeRef<SegmentNode>: SegmentNode { free_list_link: SinglyLinkedListLink });
intrusive_adapter!(pub(super) SegmentTreeAdapter = UnsafeRef<SegmentNode>: SegmentNode { tree_link: RBTreeLink });

impl<'a> KeyAdapter<'a> for SegmentTreeAdapter {
    type Key = u64;

    fn get_key(&self, node: &'a SegmentNode) -> u64 {
        node.vmem_segment.segment.start
    }
}

#[repr(C)]
struct SegmentSlab {
    slab_page: Page,
    segments: [SegmentNode; SEGMENT_NODES_IN_SMALL_PAGE],
}

const _SEGMENT_SLAB_SZ: () =
    assert!(core::mem::size_of::<SegmentSlab>() <= (PAGE_SIZE_SMALL as usize));

#[derive(Default)]
pub(super) struct SegmentMap {
    segments: RBTree<SegmentTreeAdapter>,
    free_list: SinglyLinkedList<SegmentListAdapter>,
    slab_list: SinglyLinkedList<PageListAdapter>,
    free_segment_count: u64,
    used_segment_count: u64,
    slab_count: u64,
}

impl Drop for SegmentMap {
    fn drop(&mut self) {
        debug_assert!(self.segments.is_empty());
        debug_assert!(self.free_list.is_empty());
        debug_assert!(self.slab_list.is_empty());
        assert_eq!(0, self.slab_count);
        assert_eq!(0, self.free_segment_count);
        assert_eq!(0, self.used_segment_count);
    }
}

impl SegmentMap {
    pub(super) fn is_empty(&self) -> bool {
        self.slab_count == 0
            && self.segments.is_empty()
            && self.free_list.is_empty()
            && self.slab_list.is_empty()
    }

    pub(super) fn find(&self, addr: u64) -> Option<&VmemSegment> {
        if let Some(seg) = self.segments.find(&addr).get() {
            return Some(&seg.vmem_segment);
        }

        let cursor = self
            .segments
            .upper_bound(intrusive_collections::Bound::Included(&addr));

        if let Some(seg) = cursor.get() {
            if seg.vmem_segment.segment.contains(addr) {
                return Some(&seg.vmem_segment);
            }
        }

        None
    }

    pub(super) fn get(&self, addr: &u64) -> Option<&VmemSegment> {
        self.segments.find(addr).get().map(|seg| &seg.vmem_segment)
    }

    pub(super) fn find_mut(&mut self, addr: u64) -> Option<&mut VmemSegment> {
        if let Some(seg) = self.segments.find_mut(&addr).get() {
            return Some(unsafe { seg.vmem_segment_mut() });
        }

        let cursor = self
            .segments
            .upper_bound_mut(intrusive_collections::Bound::Included(&addr));

        if let Some(seg) = cursor.get() {
            if seg.vmem_segment.segment.contains(addr) {
                return Some(unsafe { seg.vmem_segment_mut() });
            }
        }

        None
    }

    pub(super) fn intersects(&self, segment: &MemorySegment) -> bool {
        // Existing segments do not overlap. The last one starting before
        // our end intersects exactly when it ends after our start.
        self.segments
            .upper_bound(Bound::Excluded(&segment.end()))
            .get()
            .is_some_and(|seg| seg.vmem_segment.segment.end() > segment.start)
    }

    pub(super) fn get_mut(&mut self, addr: &u64) -> Option<&mut VmemSegment> {
        self.segments
            .find_mut(addr)
            .get()
            .map(|seg| unsafe { seg.vmem_segment_mut() })
    }

    /// Two distinct segments by start address, both mutable.
    pub(super) fn get_two_mut(
        &mut self,
        first: u64,
        second: u64,
    ) -> Option<(&mut VmemSegment, &mut VmemSegment)> {
        assert_ne!(first, second);
        let first = self.get_mut(&first)? as *mut VmemSegment;
        let second = self.get_mut(&second)? as *mut VmemSegment;
        // Distinct nodes of the map, so the two references never alias.
        Some(unsafe { (&mut *first, &mut *second) })
    }

    pub(super) fn last_segment(&self) -> Option<&VmemSegment> {
        if let Some(seg) = self.segments.back().get() {
            return Some(&seg.vmem_segment);
        }

        None
    }

    pub(super) fn remove(&mut self, addr: u64) -> Option<VmemSegment> {
        if let Some(seg_ref) = self.segments.find_mut(&addr).remove() {
            let seg_ptr = UnsafeRef::into_raw(seg_ref);
            let seg = unsafe { seg_ptr.as_mut().unwrap() };
            let mut result = VmemSegment::default();
            core::mem::swap(&mut result, &mut seg.vmem_segment);

            self.free_list
                .push_front(unsafe { UnsafeRef::from_raw(seg_ptr) });
            self.free_segment_count += 1;
            self.used_segment_count -= 1;

            Some(result)
        } else {
            None
        }
    }

    pub(super) fn pop_first(&mut self) -> Option<VmemSegment> {
        if let Some(seg_ref) = self.segments.front_mut().remove() {
            let seg_ptr = UnsafeRef::into_raw(seg_ref);
            let seg = unsafe { seg_ptr.as_mut().unwrap() };
            let mut result = VmemSegment::default();
            core::mem::swap(&mut result, &mut seg.vmem_segment);

            self.free_list
                .push_front(unsafe { UnsafeRef::from_raw(seg_ptr) });
            self.free_segment_count += 1;
            self.used_segment_count -= 1;

            Some(result)
        } else {
            None
        }
    }

    pub(super) fn iter(&self) -> intrusive_collections::rbtree::Iter<'_, SegmentTreeAdapter> {
        self.segments.iter()
    }

    fn alloc_slab(&mut self) {
        // Allocate a page.
        let frame = super::phys::allocate_frame(super::PageType::SmallPage);
        let virt_addr = frame.get().unwrap().start() + super::PAGING_DIRECT_MAP_OFFSET;

        // Initialize the slab page to default.
        let default_page = Page::default();
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                &default_page as *const Page,
                virt_addr as *mut Page,
                1,
            );
        }

        // Initialize segment nodes to default.
        let default_node = SegmentNode::default();
        let mut addr = virt_addr as usize + core::mem::offset_of!(SegmentSlab, segments);
        for _idx in 0..SEGMENT_NODES_IN_SMALL_PAGE {
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    &default_node as *const SegmentNode,
                    addr as *mut SegmentNode,
                    1,
                );
            }
            addr += SEGMENT_NODE_SZ;
        }

        // Get a proper segment slab.
        let mut segment_slab = MaybeUninit::<&mut SegmentSlab>::uninit();
        segment_slab.write(unsafe { (virt_addr as usize as *mut SegmentSlab).as_mut().unwrap() });
        let segment_slab = unsafe { segment_slab.assume_init() };

        // Initialize the first page.
        let slab_page = &mut segment_slab.slab_page;
        debug_assert!(slab_page.is_empty()); // We initialized it above.
        debug_assert_eq!(slab_page as *mut _ as usize, virt_addr as usize);

        slab_page.start = virt_addr;
        slab_page.frame = frame;
        slab_page.mapping_options = MappingOptions::PRIVATE;
        self.slab_list
            .push_front(unsafe { UnsafeRef::from_raw(slab_page as *const Page) });
        self.slab_count += 1;

        // Initialize the rest.
        for idx in 0..SEGMENT_NODES_IN_SMALL_PAGE {
            let node = &mut segment_slab.segments[idx];
            debug_assert!(node.is_empty());

            self.free_list
                .push_front(unsafe { UnsafeRef::from_raw(node as *const SegmentNode) });
            self.free_segment_count += 1;
        }
    }

    fn get_free_segment(&mut self) -> UnsafeRef<SegmentNode> {
        if self.free_list.is_empty() {
            self.alloc_slab();
        }

        let seg = self.free_list.pop_front().unwrap();
        self.free_segment_count -= 1;
        self.used_segment_count += 1;
        seg
    }

    pub(super) fn insert(&mut self, mut seg: VmemSegment) {
        let entry = self.get_free_segment();
        debug_assert!(entry.vmem_segment.pages.is_empty());

        unsafe {
            let entry_ptr = UnsafeRef::into_raw(entry);
            let entry_ref = entry_ptr.as_mut().unwrap();
            core::mem::swap(&mut entry_ref.vmem_segment, &mut seg);
            self.segments.insert(UnsafeRef::from_raw(entry_ptr));
        }
    }

    pub(super) fn clear(&mut self) {
        assert_eq!(0, self.used_segment_count);
        debug_assert!(self.segments.is_empty());

        self.free_list.clear();
        self.free_segment_count = 0;

        while let Some(slab_page) = self.slab_list.pop_front() {
            let page_mut = unsafe { &mut *UnsafeRef::into_raw(slab_page) };
            let frame = page_mut.frame.take();
            drop(frame);

            // Note: slab_page was backed by the frame just dropped above.
            // We should NOT touch slab_page now.
            self.slab_count -= 1;
        }

        debug_assert!(self.is_empty());
    }
}
