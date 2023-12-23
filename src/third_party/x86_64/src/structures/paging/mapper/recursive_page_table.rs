//! Access the page tables through a recursively mapped level 4 table.

use core::fmt;

use super::*;
use crate::registers::control::Cr3;
use crate::structures::paging::page_table::PageTableLevel;
use crate::structures::paging::{
    frame_alloc::FrameAllocator,
    page::{AddressNotAligned, NotGiantPageSize, PageRangeInclusive},
    page_table::{FrameError, PageTable, PageTableEntry, PageTableFlags},
    FrameDeallocator, Page, PageSize, PageTableIndex, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
};
use crate::VirtAddr;

/// A recursive page table is a last level page table with an entry mapped to the table itself.
///
/// This recursive mapping allows accessing all page tables in the hierarchy:
///
/// - To access the level 4 page table, we “loop“ (i.e. follow the recursively mapped entry) four
///   times.
/// - To access a level 3 page table, we “loop” three times and then use the level 4 index.
/// - To access a level 2 page table, we “loop” two times, then use the level 4 index, then the
///   level 3 index.
/// - To access a level 1 page table, we “loop” once, then use the level 4 index, then the
///   level 3 index, then the level 2 index.
///
/// This struct implements the `Mapper` trait.
///
/// The page table flags `PRESENT` and `WRITABLE` are always set for higher level page table
/// entries, even if not specified, because the design of the recursive page table requires it.
#[derive(Debug)]
pub struct RecursivePageTable<'a> {
    p4: &'a mut PageTable,
    recursive_index: PageTableIndex,
}

impl<'a> RecursivePageTable<'a> {
    /// Creates a new RecursivePageTable from the passed level 4 PageTable.
    ///
    /// The page table must be recursively mapped, that means:
    ///
    /// - The page table must have one recursive entry, i.e. an entry that points to the table
    ///   itself.
    ///     - The reference must use that “loop”, i.e. be of the form `0o_xxx_xxx_xxx_xxx_0000`
    ///       where `xxx` is the recursive entry.
    /// - The page table must be active, i.e. the CR3 register must contain its physical address.
    ///
    /// Otherwise `Err(())` is returned.
    #[inline]
    pub fn new(table: &'a mut PageTable) -> Result<Self, InvalidPageTable> {
        let page = Page::containing_address(VirtAddr::new(table as *const _ as u64));
        let recursive_index = page.p4_index();

        if page.p3_index() != recursive_index
            || page.p2_index() != recursive_index
            || page.p1_index() != recursive_index
        {
            return Err(InvalidPageTable::NotRecursive);
        }
        if Ok(Cr3::read().0) != table[recursive_index].frame() {
            return Err(InvalidPageTable::NotActive);
        }

        Ok(RecursivePageTable {
            p4: table,
            recursive_index,
        })
    }

    /// Creates a new RecursivePageTable without performing any checks.
    ///
    /// ## Safety
    ///
    /// The given page table must be a level 4 page table that is active in the
    /// CPU (i.e. loaded in the CR3 register). The `recursive_index` parameter
    /// must be the index of the recursively mapped entry of that page table.
    #[inline]
    pub unsafe fn new_unchecked(table: &'a mut PageTable, recursive_index: PageTableIndex) -> Self {
        RecursivePageTable {
            p4: table,
            recursive_index,
        }
    }

    /// Returns a mutable reference to the wrapped level 4 `PageTable` instance.
    pub fn level_4_table(&mut self) -> &mut PageTable {
        &mut self.p4
    }

    /// Internal helper function to create the page table of the next level if needed.
    ///
    /// If the passed entry is unused, a new frame is allocated from the given allocator, zeroed,
    /// and the entry is updated to that address. If the passed entry is already mapped, the next
    /// table is returned directly.
    ///
    /// The page table flags `PRESENT` and `WRITABLE` are always set for higher level page table
    /// entries, even if not specified in the `insert_flags`, because the design of the
    /// recursive page table requires it.
    ///
    /// The `next_page_table` page must be the page of the next page table in the hierarchy.
    ///
    /// Returns `MapToError::FrameAllocationFailed` if the entry is unused and the allocator
    /// returned `None`. Returns `MapToError::ParentEntryHugePage` if the `HUGE_PAGE` flag is set
    /// in the passed entry.
    unsafe fn create_next_table<'b, A, S: PageSize>(
        entry: &'b mut PageTableEntry,
        next_table_page: Page,
        insert_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<&'b mut PageTable, MapToError<S>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        /// This inner function is used to limit the scope of `unsafe`.
        ///
        /// This is a safe function, so we need to use `unsafe` blocks when we do something unsafe.
        fn inner<'b, A, S: PageSize>(
            entry: &'b mut PageTableEntry,
            next_table_page: Page,
            insert_flags: PageTableFlags,
            allocator: &mut A,
        ) -> Result<&'b mut PageTable, MapToError<S>>
        where
            A: FrameAllocator<Size4KiB> + ?Sized,
        {
            use crate::structures::paging::PageTableFlags as Flags;

            let created;

            if entry.is_unused() {
                if let Some(frame) = allocator.allocate_frame() {
                    entry.set_frame(frame, Flags::PRESENT | Flags::WRITABLE | insert_flags);
                    created = true;
                } else {
                    return Err(MapToError::FrameAllocationFailed);
                }
            } else {
                if !insert_flags.is_empty() && !entry.flags().contains(insert_flags) {
                    entry.set_flags(entry.flags() | insert_flags);
                }
                created = false;
            }
            if entry.flags().contains(Flags::HUGE_PAGE) {
                return Err(MapToError::ParentEntryHugePage);
            }

            let page_table_ptr = next_table_page.start_address().as_mut_ptr();
            let page_table: &mut PageTable = unsafe { &mut *(page_table_ptr) };
            if created {
                page_table.zero();
            }
            Ok(page_table)
        }

        inner(entry, next_table_page, insert_flags, allocator)
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_1gib<A>(
        &mut self,
        page: Page<Size1GiB>,
        frame: PhysFrame<Size1GiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size1GiB>, MapToError<Size1GiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        use crate::structures::paging::PageTableFlags as Flags;
        let p4 = &mut self.p4;

        let p3_page = p3_page(page, self.recursive_index);
        let p3 = unsafe {
            Self::create_next_table(
                &mut p4[page.p4_index()],
                p3_page,
                parent_table_flags,
                allocator,
            )?
        };

        if !p3[page.p3_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p3[page.p3_index()].set_addr(frame.start_address(), flags | Flags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_2mib<A>(
        &mut self,
        page: Page<Size2MiB>,
        frame: PhysFrame<Size2MiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size2MiB>, MapToError<Size2MiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        use crate::structures::paging::PageTableFlags as Flags;
        let p4 = &mut self.p4;

        let p3_page = p3_page(page, self.recursive_index);
        let p3 = unsafe {
            Self::create_next_table(
                &mut p4[page.p4_index()],
                p3_page,
                parent_table_flags,
                allocator,
            )?
        };

        let p2_page = p2_page(page, self.recursive_index);
        let p2 = unsafe {
            Self::create_next_table(
                &mut p3[page.p3_index()],
                p2_page,
                parent_table_flags,
                allocator,
            )?
        };

        if !p2[page.p2_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p2[page.p2_index()].set_addr(frame.start_address(), flags | Flags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    /// Helper function for implementing Mapper. Safe to limit the scope of unsafe, see
    /// https://github.com/rust-lang/rfcs/pull/2585.
    fn map_to_4kib<A>(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        let p4 = &mut self.p4;

        let p3_page = p3_page(page, self.recursive_index);
        let p3 = unsafe {
            Self::create_next_table(
                &mut p4[page.p4_index()],
                p3_page,
                parent_table_flags,
                allocator,
            )?
        };

        let p2_page = p2_page(page, self.recursive_index);
        let p2 = unsafe {
            Self::create_next_table(
                &mut p3[page.p3_index()],
                p2_page,
                parent_table_flags,
                allocator,
            )?
        };

        let p1_page = p1_page(page, self.recursive_index);
        let p1 = unsafe {
            Self::create_next_table(
                &mut p2[page.p2_index()],
                p1_page,
                parent_table_flags,
                allocator,
            )?
        };

        if !p1[page.p1_index()].is_unused() {
            return Err(MapToError::PageAlreadyMapped(frame));
        }
        p1[page.p1_index()].set_frame(frame, flags);

        Ok(MapperFlush::new(page))
    }
}

impl<'a> Mapper<Size1GiB> for RecursivePageTable<'a> {
    #[inline]
    unsafe fn map_to_with_table_flags<A>(
        &mut self,
        page: Page<Size1GiB>,
        frame: PhysFrame<Size1GiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size1GiB>, MapToError<Size1GiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        self.map_to_1gib(page, frame, flags, parent_table_flags, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size1GiB>,
    ) -> Result<(PhysFrame<Size1GiB>, MapperFlush<Size1GiB>), UnmapError> {
        let p4 = &mut self.p4;
        let p4_entry = &p4[page.p4_index()];

        p4_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &mut p3[page.p3_index()];
        let flags = p3_entry.flags();

        if !flags.contains(PageTableFlags::PRESENT) {
            return Err(UnmapError::PageNotMapped);
        }
        if !flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(UnmapError::ParentEntryHugePage);
        }

        let frame = PhysFrame::from_start_address(p3_entry.addr())
            .map_err(|AddressNotAligned| UnmapError::InvalidFrameAddress(p3_entry.addr()))?;

        p3_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    unsafe fn update_flags(
        &mut self,
        page: Page<Size1GiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size1GiB>, FlagUpdateError> {
        use crate::structures::paging::PageTableFlags as Flags;
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };

        if p3[page.p3_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }
        p3[page.p3_index()].set_flags(flags | Flags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    unsafe fn set_flags_p4_entry(
        &mut self,
        page: Page<Size1GiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;
        let p4_entry = &mut p4[page.p4_index()];

        if p4_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p4_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    unsafe fn set_flags_p3_entry(
        &mut self,
        _page: Page<Size1GiB>,
        _flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        Err(FlagUpdateError::ParentEntryHugePage)
    }

    unsafe fn set_flags_p2_entry(
        &mut self,
        _page: Page<Size1GiB>,
        _flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        Err(FlagUpdateError::ParentEntryHugePage)
    }

    fn translate_page(&self, page: Page<Size1GiB>) -> Result<PhysFrame<Size1GiB>, TranslateError> {
        let p4 = &self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p3 = unsafe { &*(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p3_entry.addr())
            .map_err(|AddressNotAligned| TranslateError::InvalidFrameAddress(p3_entry.addr()))
    }
}

impl<'a> Mapper<Size2MiB> for RecursivePageTable<'a> {
    #[inline]
    unsafe fn map_to_with_table_flags<A>(
        &mut self,
        page: Page<Size2MiB>,
        frame: PhysFrame<Size2MiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size2MiB>, MapToError<Size2MiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        self.map_to_2mib(page, frame, flags, parent_table_flags, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size2MiB>,
    ) -> Result<(PhysFrame<Size2MiB>, MapperFlush<Size2MiB>), UnmapError> {
        let p4 = &mut self.p4;
        let p4_entry = &p4[page.p4_index()];
        p4_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[page.p3_index()];
        p3_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p2 = unsafe { &mut *(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &mut p2[page.p2_index()];
        let flags = p2_entry.flags();

        if !flags.contains(PageTableFlags::PRESENT) {
            return Err(UnmapError::PageNotMapped);
        }
        if !flags.contains(PageTableFlags::HUGE_PAGE) {
            return Err(UnmapError::ParentEntryHugePage);
        }

        let frame = PhysFrame::from_start_address(p2_entry.addr())
            .map_err(|AddressNotAligned| UnmapError::InvalidFrameAddress(p2_entry.addr()))?;

        p2_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    unsafe fn update_flags(
        &mut self,
        page: Page<Size2MiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size2MiB>, FlagUpdateError> {
        use crate::structures::paging::PageTableFlags as Flags;
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };

        if p3[page.p3_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p2 = unsafe { &mut *(p2_ptr(page, self.recursive_index)) };

        if p2[page.p2_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p2[page.p2_index()].set_flags(flags | Flags::HUGE_PAGE);

        Ok(MapperFlush::new(page))
    }

    unsafe fn set_flags_p4_entry(
        &mut self,
        page: Page<Size2MiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;
        let p4_entry = &mut p4[page.p4_index()];

        if p4_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p4_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    unsafe fn set_flags_p3_entry(
        &mut self,
        page: Page<Size2MiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &mut p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p3_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    unsafe fn set_flags_p2_entry(
        &mut self,
        _page: Page<Size2MiB>,
        _flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        Err(FlagUpdateError::ParentEntryHugePage)
    }

    fn translate_page(&self, page: Page<Size2MiB>) -> Result<PhysFrame<Size2MiB>, TranslateError> {
        let p4 = &self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p3 = unsafe { &*(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p2 = unsafe { &*(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &p2[page.p2_index()];

        if p2_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p2_entry.addr())
            .map_err(|AddressNotAligned| TranslateError::InvalidFrameAddress(p2_entry.addr()))
    }
}

impl<'a> Mapper<Size4KiB> for RecursivePageTable<'a> {
    #[inline]
    unsafe fn map_to_with_table_flags<A>(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
        parent_table_flags: PageTableFlags,
        allocator: &mut A,
    ) -> Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>>
    where
        A: FrameAllocator<Size4KiB> + ?Sized,
    {
        self.map_to_4kib(page, frame, flags, parent_table_flags, allocator)
    }

    fn unmap(
        &mut self,
        page: Page<Size4KiB>,
    ) -> Result<(PhysFrame<Size4KiB>, MapperFlush<Size4KiB>), UnmapError> {
        let p4 = &mut self.p4;
        let p4_entry = &p4[page.p4_index()];
        p4_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[page.p3_index()];
        p3_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p2 = unsafe { &mut *(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &p2[page.p2_index()];
        p2_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        let p1 = unsafe { &mut *(p1_ptr(page, self.recursive_index)) };
        let p1_entry = &mut p1[page.p1_index()];

        let frame = p1_entry.frame().map_err(|err| match err {
            FrameError::FrameNotPresent => UnmapError::PageNotMapped,
            FrameError::HugeFrame => UnmapError::ParentEntryHugePage,
        })?;

        p1_entry.set_unused();
        Ok((frame, MapperFlush::new(page)))
    }

    unsafe fn update_flags(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<Size4KiB>, FlagUpdateError> {
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };

        if p3[page.p3_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p2 = unsafe { &mut *(p2_ptr(page, self.recursive_index)) };

        if p2[page.p2_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p1 = unsafe { &mut *(p1_ptr(page, self.recursive_index)) };

        if p1[page.p1_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p1[page.p1_index()].set_flags(flags);

        Ok(MapperFlush::new(page))
    }

    unsafe fn set_flags_p4_entry(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;
        let p4_entry = &mut p4[page.p4_index()];

        if p4_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p4_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    unsafe fn set_flags_p3_entry(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &mut p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p3_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    unsafe fn set_flags_p2_entry(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<MapperFlushAll, FlagUpdateError> {
        let p4 = &mut self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p3 = unsafe { &mut *(p3_ptr(page, self.recursive_index)) };

        if p3[page.p3_index()].is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        let p2 = unsafe { &mut *(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &mut p2[page.p2_index()];

        if p2_entry.is_unused() {
            return Err(FlagUpdateError::PageNotMapped);
        }

        p2_entry.set_flags(flags);

        Ok(MapperFlushAll::new())
    }

    fn translate_page(&self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, TranslateError> {
        let p4 = &self.p4;

        if p4[page.p4_index()].is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p3 = unsafe { &*(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[page.p3_index()];

        if p3_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p2 = unsafe { &*(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &p2[page.p2_index()];

        if p2_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        let p1 = unsafe { &*(p1_ptr(page, self.recursive_index)) };
        let p1_entry = &p1[page.p1_index()];

        if p1_entry.is_unused() {
            return Err(TranslateError::PageNotMapped);
        }

        PhysFrame::from_start_address(p1_entry.addr())
            .map_err(|AddressNotAligned| TranslateError::InvalidFrameAddress(p1_entry.addr()))
    }
}

impl<'a> Translate for RecursivePageTable<'a> {
    #[allow(clippy::inconsistent_digit_grouping)]
    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        let page = Page::containing_address(addr);

        let p4 = &self.p4;
        let p4_entry = &p4[addr.p4_index()];
        if p4_entry.is_unused() {
            return TranslateResult::NotMapped;
        }
        if p4_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            panic!("level 4 entry has huge page bit set")
        }

        let p3 = unsafe { &*(p3_ptr(page, self.recursive_index)) };
        let p3_entry = &p3[addr.p3_index()];
        if p3_entry.is_unused() {
            return TranslateResult::NotMapped;
        }
        if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            let entry = &p3[addr.p3_index()];
            let frame = PhysFrame::containing_address(entry.addr());
            let offset = addr.as_u64() & 0o_777_777_7777;
            let flags = entry.flags();
            return TranslateResult::Mapped {
                frame: MappedFrame::Size1GiB(frame),
                offset,
                flags,
            };
        }

        let p2 = unsafe { &*(p2_ptr(page, self.recursive_index)) };
        let p2_entry = &p2[addr.p2_index()];
        if p2_entry.is_unused() {
            return TranslateResult::NotMapped;
        }
        if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            let entry = &p2[addr.p2_index()];
            let frame = PhysFrame::containing_address(entry.addr());
            let offset = addr.as_u64() & 0o_777_7777;
            let flags = entry.flags();
            return TranslateResult::Mapped {
                frame: MappedFrame::Size2MiB(frame),
                offset,
                flags,
            };
        }

        let p1 = unsafe { &*(p1_ptr(page, self.recursive_index)) };
        let p1_entry = &p1[addr.p1_index()];
        if p1_entry.is_unused() {
            return TranslateResult::NotMapped;
        }
        if p1_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            panic!("level 1 entry has huge page bit set")
        }

        let frame = match PhysFrame::from_start_address(p1_entry.addr()) {
            Ok(frame) => frame,
            Err(AddressNotAligned) => return TranslateResult::InvalidFrameAddress(p1_entry.addr()),
        };
        let offset = u64::from(addr.page_offset());
        let flags = p1_entry.flags();
        TranslateResult::Mapped {
            frame: MappedFrame::Size4KiB(frame),
            offset,
            flags,
        }
    }
}

impl<'a> CleanUp for RecursivePageTable<'a> {
    #[inline]
    unsafe fn clean_up<D>(&mut self, frame_deallocator: &mut D)
    where
        D: FrameDeallocator<Size4KiB>,
    {
        unsafe {
            self.clean_up_addr_range(
                PageRangeInclusive {
                    start: Page::from_start_address(VirtAddr::new(0)).unwrap(),
                    end: Page::from_start_address(VirtAddr::new(0xffff_ffff_ffff_f000)).unwrap(),
                },
                frame_deallocator,
            )
        }
    }

    unsafe fn clean_up_addr_range<D>(
        &mut self,
        range: PageRangeInclusive,
        frame_deallocator: &mut D,
    ) where
        D: FrameDeallocator<Size4KiB>,
    {
        fn clean_up(
            recursive_index: PageTableIndex,
            page_table: &mut PageTable,
            level: PageTableLevel,
            range: PageRangeInclusive,
            frame_deallocator: &mut impl FrameDeallocator<Size4KiB>,
        ) -> bool {
            if range.is_empty() {
                return false;
            }

            let table_addr = range
                .start
                .start_address()
                .align_down(level.table_address_space_alignment());

            let start = range.start.page_table_index(level);
            let end = range.end.page_table_index(level);

            if let Some(next_level) = level.next_lower_level() {
                let offset_per_entry = level.entry_address_space_alignment();
                for (i, entry) in page_table
                    .iter_mut()
                    .enumerate()
                    .take(usize::from(end) + 1)
                    .skip(usize::from(start))
                    .filter(|(i, _)| {
                        !(level == PageTableLevel::Four && *i == recursive_index.into())
                    })
                {
                    if let Ok(frame) = entry.frame() {
                        let start = table_addr + (offset_per_entry * (i as u64));
                        let end = start + (offset_per_entry - 1);
                        let start = Page::<Size4KiB>::containing_address(start);
                        let start = start.max(range.start);
                        let end = Page::<Size4KiB>::containing_address(end);
                        let end = end.min(range.end);
                        let page_table =
                            [p1_ptr, p2_ptr, p3_ptr][level as usize - 2](start, recursive_index);
                        let page_table = unsafe { &mut *page_table };
                        if clean_up(
                            recursive_index,
                            page_table,
                            next_level,
                            Page::range_inclusive(start, end),
                            frame_deallocator,
                        ) {
                            entry.set_unused();
                            unsafe {
                                frame_deallocator.deallocate_frame(frame);
                            }
                        }
                    }
                }
            }

            page_table.iter().all(PageTableEntry::is_unused)
        }

        clean_up(
            self.recursive_index,
            self.level_4_table(),
            PageTableLevel::Four,
            range,
            frame_deallocator,
        );
    }
}

/// The given page table was not suitable to create a `RecursivePageTable`.
#[derive(Debug)]
pub enum InvalidPageTable {
    /// The given page table was not at an recursive address.
    ///
    /// The page table address must be of the form `0o_xxx_xxx_xxx_xxx_0000` where `xxx`
    /// is the recursive entry.
    NotRecursive,
    /// The given page table was not active on the CPU.
    ///
    /// The recursive page table design requires that the given level 4 table is active
    /// on the CPU because otherwise it's not possible to access the other page tables
    /// through recursive memory addresses.
    NotActive,
}

impl fmt::Display for InvalidPageTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidPageTable::NotRecursive => {
                write!(f, "given page table address is not recursive")
            }
            InvalidPageTable::NotActive => write!(f, "given page table is not active on the CPU"),
        }
    }
}

#[inline]
fn p3_ptr<S: PageSize>(page: Page<S>, recursive_index: PageTableIndex) -> *mut PageTable {
    p3_page(page, recursive_index).start_address().as_mut_ptr()
}

#[inline]
fn p3_page<S: PageSize>(page: Page<S>, recursive_index: PageTableIndex) -> Page {
    Page::from_page_table_indices(
        recursive_index,
        recursive_index,
        recursive_index,
        page.p4_index(),
    )
}

#[inline]
fn p2_ptr<S: NotGiantPageSize>(page: Page<S>, recursive_index: PageTableIndex) -> *mut PageTable {
    p2_page(page, recursive_index).start_address().as_mut_ptr()
}

#[inline]
fn p2_page<S: NotGiantPageSize>(page: Page<S>, recursive_index: PageTableIndex) -> Page {
    Page::from_page_table_indices(
        recursive_index,
        recursive_index,
        page.p4_index(),
        page.p3_index(),
    )
}

#[inline]
fn p1_ptr(page: Page<Size4KiB>, recursive_index: PageTableIndex) -> *mut PageTable {
    p1_page(page, recursive_index).start_address().as_mut_ptr()
}

#[inline]
fn p1_page(page: Page<Size4KiB>, recursive_index: PageTableIndex) -> Page {
    Page::from_page_table_indices(
        recursive_index,
        page.p4_index(),
        page.p3_index(),
        page.p2_index(),
    )
}
