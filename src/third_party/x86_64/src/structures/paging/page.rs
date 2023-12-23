//! Abstractions for default-sized and huge virtual memory pages.

use crate::structures::paging::page_table::PageTableLevel;
use crate::structures::paging::PageTableIndex;
use crate::VirtAddr;
use core::fmt;
#[cfg(feature = "step_trait")]
use core::iter::Step;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// Trait for abstracting over the three possible page sizes on x86_64, 4KiB, 2MiB, 1GiB.
pub trait PageSize: Copy + Eq + PartialOrd + Ord {
    /// The page size in bytes.
    const SIZE: u64;

    /// A string representation of the page size for debug output.
    const SIZE_AS_DEBUG_STR: &'static str;
}

/// This trait is implemented for 4KiB and 2MiB pages, but not for 1GiB pages.
pub trait NotGiantPageSize: PageSize {}

/// A standard 4KiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size4KiB {}

/// A “huge” 2MiB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size2MiB {}

/// A “giant” 1GiB page.
///
/// (Only available on newer x86_64 CPUs.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Size1GiB {}

impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
    const SIZE_AS_DEBUG_STR: &'static str = "4KiB";
}

impl NotGiantPageSize for Size4KiB {}

impl PageSize for Size2MiB {
    const SIZE: u64 = Size4KiB::SIZE * 512;
    const SIZE_AS_DEBUG_STR: &'static str = "2MiB";
}

impl NotGiantPageSize for Size2MiB {}

impl PageSize for Size1GiB {
    const SIZE: u64 = Size2MiB::SIZE * 512;
    const SIZE_AS_DEBUG_STR: &'static str = "1GiB";
}

/// A virtual memory page.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct Page<S: PageSize = Size4KiB> {
    start_address: VirtAddr,
    size: PhantomData<S>,
}

impl<S: PageSize> Page<S> {
    /// The page size in bytes.
    pub const SIZE: u64 = S::SIZE;

    /// Returns the page that starts at the given virtual address.
    ///
    /// Returns an error if the address is not correctly aligned (i.e. is not a valid page start).
    #[inline]
    pub fn from_start_address(address: VirtAddr) -> Result<Self, AddressNotAligned> {
        if !address.is_aligned(S::SIZE) {
            return Err(AddressNotAligned);
        }
        Ok(Page::containing_address(address))
    }

    /// Returns the page that starts at the given virtual address.
    ///
    /// ## Safety
    ///
    /// The address must be correctly aligned.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub unsafe fn from_start_address_unchecked(start_address: VirtAddr) -> Self {
        Page {
            start_address,
            size: PhantomData,
        }
    }

    /// Returns the page that contains the given virtual address.
    #[inline]
    pub fn containing_address(address: VirtAddr) -> Self {
        Page {
            start_address: address.align_down(S::SIZE),
            size: PhantomData,
        }
    }

    /// Returns the start address of the page.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn start_address(self) -> VirtAddr {
        self.start_address
    }

    /// Returns the size the page (4KB, 2MB or 1GB).
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn size(self) -> u64 {
        S::SIZE
    }

    /// Returns the level 4 page table index of this page.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn p4_index(self) -> PageTableIndex {
        self.start_address().p4_index()
    }

    /// Returns the level 3 page table index of this page.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn p3_index(self) -> PageTableIndex {
        self.start_address().p3_index()
    }

    /// Returns the table index of this page at the specified level.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn page_table_index(self, level: PageTableLevel) -> PageTableIndex {
        self.start_address().page_table_index(level)
    }

    /// Returns a range of pages, exclusive `end`.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn range(start: Self, end: Self) -> PageRange<S> {
        PageRange { start, end }
    }

    /// Returns a range of pages, inclusive `end`.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn range_inclusive(start: Self, end: Self) -> PageRangeInclusive<S> {
        PageRangeInclusive { start, end }
    }
}

impl<S: NotGiantPageSize> Page<S> {
    /// Returns the level 2 page table index of this page.
    #[inline]
    #[rustversion::attr(since(1.61), const)]
    pub fn p2_index(self) -> PageTableIndex {
        self.start_address().p2_index()
    }
}

impl Page<Size1GiB> {
    /// Returns the 1GiB memory page with the specified page table indices.
    #[inline]
    pub fn from_page_table_indices_1gib(
        p4_index: PageTableIndex,
        p3_index: PageTableIndex,
    ) -> Self {
        use bit_field::BitField;

        let mut addr = 0;
        addr.set_bits(39..48, u64::from(p4_index));
        addr.set_bits(30..39, u64::from(p3_index));
        Page::containing_address(VirtAddr::new(addr))
    }
}

impl Page<Size2MiB> {
    /// Returns the 2MiB memory page with the specified page table indices.
    #[inline]
    pub fn from_page_table_indices_2mib(
        p4_index: PageTableIndex,
        p3_index: PageTableIndex,
        p2_index: PageTableIndex,
    ) -> Self {
        use bit_field::BitField;

        let mut addr = 0;
        addr.set_bits(39..48, u64::from(p4_index));
        addr.set_bits(30..39, u64::from(p3_index));
        addr.set_bits(21..30, u64::from(p2_index));
        Page::containing_address(VirtAddr::new(addr))
    }
}

impl Page<Size4KiB> {
    /// Returns the 4KiB memory page with the specified page table indices.
    #[inline]
    pub fn from_page_table_indices(
        p4_index: PageTableIndex,
        p3_index: PageTableIndex,
        p2_index: PageTableIndex,
        p1_index: PageTableIndex,
    ) -> Self {
        use bit_field::BitField;

        let mut addr = 0;
        addr.set_bits(39..48, u64::from(p4_index));
        addr.set_bits(30..39, u64::from(p3_index));
        addr.set_bits(21..30, u64::from(p2_index));
        addr.set_bits(12..21, u64::from(p1_index));
        Page::containing_address(VirtAddr::new(addr))
    }

    /// Returns the level 1 page table index of this page.
    #[inline]
    pub const fn p1_index(self) -> PageTableIndex {
        self.start_address.p1_index()
    }
}

impl<S: PageSize> fmt::Debug for Page<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "Page[{}]({:#x})",
            S::SIZE_AS_DEBUG_STR,
            self.start_address().as_u64()
        ))
    }
}

impl<S: PageSize> Add<u64> for Page<S> {
    type Output = Self;
    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Page::containing_address(self.start_address() + rhs * S::SIZE)
    }
}

impl<S: PageSize> AddAssign<u64> for Page<S> {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}

impl<S: PageSize> Sub<u64> for Page<S> {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Page::containing_address(self.start_address() - rhs * S::SIZE)
    }
}

impl<S: PageSize> SubAssign<u64> for Page<S> {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        *self = *self - rhs;
    }
}

impl<S: PageSize> Sub<Self> for Page<S> {
    type Output = u64;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        (self.start_address - rhs.start_address) / S::SIZE
    }
}

#[cfg(feature = "step_trait")]
impl<S: PageSize> Step for Page<S> {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        Step::steps_between(&start.start_address, &end.start_address)
            .map(|steps| steps / S::SIZE as usize)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        let count = count.checked_mul(S::SIZE as usize)?;
        let start_address = Step::forward_checked(start.start_address, count)?;
        Some(Self {
            start_address,
            size: PhantomData,
        })
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        let count = count.checked_mul(S::SIZE as usize)?;
        let start_address = Step::backward_checked(start.start_address, count)?;
        Some(Self {
            start_address,
            size: PhantomData,
        })
    }
}

/// A range of pages with exclusive upper bound.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct PageRange<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: Page<S>,
    /// The end of the range, exclusive.
    pub end: Page<S>,
}

impl<S: PageSize> PageRange<S> {
    /// Returns wether this range contains no pages.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

impl<S: PageSize> Iterator for PageRange<S> {
    type Item = Page<S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let page = self.start;
            self.start += 1;
            Some(page)
        } else {
            None
        }
    }
}

impl PageRange<Size2MiB> {
    /// Converts the range of 2MiB pages to a range of 4KiB pages.
    #[inline]
    pub fn as_4kib_page_range(self) -> PageRange<Size4KiB> {
        PageRange {
            start: Page::containing_address(self.start.start_address()),
            end: Page::containing_address(self.end.start_address()),
        }
    }
}

impl<S: PageSize> fmt::Debug for PageRange<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PageRange")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// A range of pages with inclusive upper bound.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct PageRangeInclusive<S: PageSize = Size4KiB> {
    /// The start of the range, inclusive.
    pub start: Page<S>,
    /// The end of the range, inclusive.
    pub end: Page<S>,
}

impl<S: PageSize> PageRangeInclusive<S> {
    /// Returns wether this range contains no pages.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

impl<S: PageSize> Iterator for PageRangeInclusive<S> {
    type Item = Page<S>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start <= self.end {
            let page = self.start;

            // If the end of the inclusive range is the maximum page possible for size S,
            // incrementing start until it is greater than the end will cause an integer overflow.
            // So instead, in that case we decrement end rather than incrementing start.
            let max_page_addr = VirtAddr::new(u64::MAX) - (S::SIZE - 1);
            if self.start.start_address() < max_page_addr {
                self.start += 1;
            } else {
                self.end -= 1;
            }
            Some(page)
        } else {
            None
        }
    }
}

impl<S: PageSize> fmt::Debug for PageRangeInclusive<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PageRangeInclusive")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// The given address was not sufficiently aligned.
#[derive(Debug)]
pub struct AddressNotAligned;

impl fmt::Display for AddressNotAligned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the given address was not sufficiently aligned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_page_ranges() {
        let page_size = Size4KiB::SIZE;
        let number = 1000;

        let start_addr = VirtAddr::new(0xdead_beaf);
        let start: Page = Page::containing_address(start_addr);
        let end = start + number;

        let mut range = Page::range(start, end);
        for i in 0..number {
            assert_eq!(
                range.next(),
                Some(Page::containing_address(start_addr + page_size * i))
            );
        }
        assert_eq!(range.next(), None);

        let mut range_inclusive = Page::range_inclusive(start, end);
        for i in 0..=number {
            assert_eq!(
                range_inclusive.next(),
                Some(Page::containing_address(start_addr + page_size * i))
            );
        }
        assert_eq!(range_inclusive.next(), None);
    }

    #[test]
    pub fn test_page_range_inclusive_overflow() {
        let page_size = Size4KiB::SIZE;
        let number = 1000;

        let start_addr = VirtAddr::new(u64::MAX).align_down(page_size) - number * page_size;
        let start: Page = Page::containing_address(start_addr);
        let end = start + number;

        let mut range_inclusive = Page::range_inclusive(start, end);
        for i in 0..=number {
            assert_eq!(
                range_inclusive.next(),
                Some(Page::containing_address(start_addr + page_size * i))
            );
        }
        assert_eq!(range_inclusive.next(), None);
    }
}
