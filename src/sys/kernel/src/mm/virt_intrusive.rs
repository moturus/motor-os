// This module contains data structures used in virtual memory management that
// utilize intrusive collections: using normal vectors/maps is not right, as
// they involve heap allocations, and we don't want to do heap allocations
// while allocating virtual memory, as it results in nasty recursion.
use core::mem::MaybeUninit;
use intrusive_collections::{intrusive_adapter, UnsafeRef};
use intrusive_collections::{KeyAdapter, RBTree, RBTreeLink};
use intrusive_collections::{SinglyLinkedList, SinglyLinkedListLink};
use moto_sys::ErrorCode;

use crate::mm::{PageType, PAGE_SIZE_SMALL_LOG2};
use crate::util::SpinLock;

use super::phys::Frame;
use super::slab::SlabArc;
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

    fn contains(&self, vmem_addr: u64) -> bool {
        (self.start <= vmem_addr) && (vmem_addr < (self.start + PAGE_SIZE_SMALL))
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

    fn alloc_page(&mut self) -> Result<*mut Page, moto_sys::ErrorCode> {
        if self.free_list.is_empty() {
            debug_assert_eq!(0, self.free_page_count);

            self.alloc_slab()?;
        }

        let page = self.free_list.pop_front().unwrap();
        debug_assert!(page.is_empty());
        self.free_page_count -= 1;
        self.used_page_count += 1;

        Ok(UnsafeRef::into_raw(page))
    }

    fn free_page(&mut self, page: *mut Page) {
        #[cfg(debug_assertions)]
        assert!(unsafe { page.as_ref().unwrap().is_empty() });

        self.free_list
            .push_front(unsafe { UnsafeRef::from_raw(page) });
        self.free_page_count += 1;
        self.used_page_count -= 1;
    }

    fn alloc_slab(&mut self) -> Result<(), moto_sys::ErrorCode> {
        // Allocate a page. Note that we don't need to map the frame/page here,
        // as all phys mem has been mapped at PAGING_DIRECT_MAP_OFFSET.
        let frame = super::phys::allocate_frame(super::PageType::SmallPage)?;
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

        Ok(())
    }
}

#[derive(Default)]
pub(super) struct PageAllocator {
    inner: SpinLock<PageAllocatorInner>,
}

impl PageAllocator {
    fn alloc_page(&self) -> Result<*mut Page, moto_sys::ErrorCode> {
        self.inner.lock(line!()).alloc_page()
    }

    fn free_page(&self, page: *mut Page) {
        self.inner.lock(line!()).free_page(page)
    }

    pub(super) fn clear(&self) {
        self.inner.lock(line!()).clear()
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

    fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    pub(super) fn segment(&self) -> MemorySegment {
        self.segment
    }

    fn find_page(&self, vmem_addr: u64) -> Option<&Page> {
        let page_addr = vmem_addr & !(PAGE_SIZE_SMALL - 1);
        self.pages.find(&page_addr).get()
    }

    fn find_page_mut(&mut self, vmem_addr: u64) -> Option<&mut Page> {
        let page_addr = vmem_addr & !(PAGE_SIZE_SMALL - 1);
        self.pages
            .find(&page_addr)
            .clone_pointer()
            .map(|ptr| unsafe { UnsafeRef::into_raw(ptr).as_mut().unwrap() })
    }

    pub(super) fn vaddr_map_status(&self, vmem_addr: u64) -> VaddrMapStatus {
        assert!(self.segment.contains(vmem_addr));

        let page = self.find_page(vmem_addr).unwrap();

        if let Some(frame) = page.frame.get() {
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

    pub(super) fn unmap(mut self) -> u64 {
        // Note: it is important to unmap pages before freeing the segment
        // in the VMemRegion, otherwise a concurrent allocation may try
        // to map a page that is not yet unmapped.
        self.clear()
    }

    fn clear_page(&mut self, page: UnsafeRef<Page>) {
        let page_ptr = UnsafeRef::into_raw(page);
        let page_mut = unsafe { page_ptr.as_mut().unwrap() };
        let frame = page_mut.frame.take();
        if let Some(frame) = frame.get() {
            self.address_space().page_table.unmap_page(
                frame.start(),
                page_mut.start,
                PageType::SmallPage,
            );
        }

        page_mut.clear();
        self.address_space().page_allocator.free_page(page_ptr);
    }

    fn clear(&mut self) -> u64 {
        debug_assert_ne!(self.segment.size, 0);
        debug_assert!(!self.owner.is_null());

        let mut pages = self.pages.take();
        let mut cursor = pages.front_mut();
        let mut sz = 0;

        while let Some(page) = cursor.remove() {
            self.clear_page(page);
            sz += PAGE_SIZE_SMALL;
        }

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

    pub(super) fn allocate_pages(&mut self) -> Result<(), ErrorCode> {
        assert!(self.segment.size > 0);
        assert!(self.pages.is_empty());

        let num_pages = self.segment.size >> PAGE_SIZE_SMALL_LOG2;
        let mut start = self.segment.start;
        for idx in 0..num_pages {
            // Allocate a vmem page.
            let page = match self.address_space().page_allocator.alloc_page() {
                Ok(page) => page,
                Err(err) => {
                    self.clear();
                    log::error!("failed to allocate a frame");
                    return Err(err);
                }
            };
            let page_mut = unsafe { page.as_mut() }.unwrap();
            debug_assert!(page_mut.is_empty());
            page_mut.start = start;

            // Determine mapping options for the page.
            let page_options = {
                if self.mapping_options.contains(MappingOptions::GUARD) {
                    if idx == 0 || idx == (num_pages - 1) {
                        MappingOptions::empty()
                    } else {
                        self.mapping_options
                            .difference(MappingOptions::GUARD | MappingOptions::LAZY)
                    }
                } else {
                    self.mapping_options
                }
            };
            page_mut.mapping_options = page_options;

            // Map, if needed.
            if !page_options.is_empty() && !self.mapping_options.contains(MappingOptions::LAZY) {
                // Allocate a frame.
                let frame = match super::phys::allocate_frame(PageType::SmallPage) {
                    Ok(frame) => frame,
                    Err(err) => {
                        assert!(!page_mut.list_link.is_linked()); // TODO: remove.
                        page_mut.clear();
                        self.address_space().page_allocator.free_page(page);
                        self.clear();
                        log::error!("failed to allocate a frame");
                        return Err(err);
                    }
                };

                // Map the frame.
                self.address_space().page_table.map_page(
                    frame.get().unwrap().start(),
                    start,
                    PageType::SmallPage,
                    page_options,
                );

                // Store the frame in the page.
                page_mut.frame = frame;
            }

            // Insert the page.
            self.pages.insert(unsafe { UnsafeRef::from_raw(page) });

            start += PAGE_SIZE_SMALL;
        }

        Ok(())
    }

    pub fn mmio_map(&self, phys_addr: u64, user: bool) -> Result<(), ErrorCode> {
        let pt = &self.address_space().page_table;
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
            super::phys::fixed_addr_reserve(phys_addr + offset, PageType::SmallPage)?;
            pt.map_page(
                phys_addr + offset,
                start + offset,
                PageType::SmallPage,
                options,
            );
            offset += PAGE_SIZE_SMALL;
        }

        Ok(())
    }

    pub(super) fn fix_pagefault(&mut self, pf_addr: u64, error_code: u64) -> Result<(), ErrorCode> {
        debug_assert!(self.segment.contains(pf_addr));

        if (((pf_addr & !(PAGE_SIZE_SMALL - 1)) == self.segment.start)
            || (pf_addr >= (self.segment.end() - PAGE_SIZE_SMALL)))
            && self.mapping_options.contains(MappingOptions::GUARD)
        {
            log::debug!("#PF: guard page");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        debug_assert_eq!(error_code & 4, 4);
        let error_code = error_code ^ 4;

        let page = self.find_page_mut(pf_addr).unwrap();
        assert!(page.contains(pf_addr));

        if !page.frame.is_null() {
            log::error!("#PF with a frame present.");
            return Err(moto_rt::E_INVALID_ARGUMENT);
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

        page.frame = super::phys::allocate_frame(PageType::SmallPage)?;
        let mut mapping_options = page.mapping_options;
        mapping_options.remove(MappingOptions::LAZY);
        mapping_options.remove(MappingOptions::GUARD);

        let phys_addr = page.frame.get().unwrap().start();
        let virt_addr = page.start;
        let page_type = PageType::SmallPage;
        self.address_space()
            .page_table
            .map_page(phys_addr, virt_addr, page_type, mapping_options);

        Ok(())
    }

    pub(super) fn share_with(
        &self,
        other: &mut Self,
        mapping_options: MappingOptions,
    ) -> Result<(), ErrorCode> {
        debug_assert_eq!(self.segment.size, other.segment.size);
        debug_assert!(!self.pages.is_empty());
        debug_assert!(!other.pages.is_empty());
        debug_assert_eq!(self.segment.size, other.segment.size);

        let mut self_cursor = self.pages.front();
        let mut other_cursor = other.pages.front();
        while !self_cursor.is_null() {
            let self_page = self_cursor.get();
            let other_page = other_cursor
                .clone_pointer()
                .map(|ptr| unsafe { UnsafeRef::into_raw(ptr).as_mut().unwrap() });

            let this_page = self_page.unwrap();
            let that_page = other_page.unwrap();

            assert!(!this_page.frame.is_null());
            // assert!(that_page.frame.is_null());
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
            );

            self_cursor.move_next();
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
        if let Some(seg) = self
            .segments
            .upper_bound(intrusive_collections::Bound::Included(&segment.end()))
            .get()
        {
            if seg.vmem_segment.segment.contains(segment.start) {
                return true;
            }
        }

        false
    }

    pub(super) fn get_mut(&mut self, addr: &u64) -> Option<&mut VmemSegment> {
        self.segments
            .find_mut(addr)
            .get()
            .map(|seg| unsafe { seg.vmem_segment_mut() })
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

    fn alloc_slab(&mut self) -> Result<(), moto_sys::ErrorCode> {
        // Allocate a page.
        let frame = super::phys::allocate_frame(super::PageType::SmallPage)?;
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

        Ok(())
    }

    fn get_free_segment(&mut self) -> UnsafeRef<SegmentNode> {
        if self.free_list.is_empty() {
            self.alloc_slab().unwrap();
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
