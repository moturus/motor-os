//! Abstractions for page tables and other paging related structures.
//!
//! Page tables translate virtual memory “pages” to physical memory “frames”.

pub use self::frame::PhysFrame;
pub use self::frame_alloc::{FrameAllocator, FrameDeallocator};
#[doc(no_inline)]
pub use self::mapper::MappedPageTable;
#[cfg(target_pointer_width = "64")]
#[doc(no_inline)]
pub use self::mapper::OffsetPageTable;
#[cfg(feature = "instructions")]
#[doc(no_inline)]
pub use self::mapper::RecursivePageTable;
pub use self::mapper::{Mapper, Translate};
pub use self::page::{Page, PageSize, Size1GiB, Size2MiB, Size4KiB};
pub use self::page_table::{PageOffset, PageTable, PageTableFlags, PageTableIndex};

pub mod frame;
mod frame_alloc;
pub mod mapper;
pub mod page;
pub mod page_table;
