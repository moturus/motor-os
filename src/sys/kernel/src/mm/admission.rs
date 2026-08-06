//! Low-memory admission control: see docs/plans/kernel-oom.md.
//!
//! Userspace operations that grow physical memory must be admitted first.
//! Admission refuses them while a guard band of small pages is still free, so
//! the physical allocator never empties and panics the kernel. Charges are
//! conservative upper bounds, not exact bills, and are held as atomic
//! reservations for the duration of the operation, which makes concurrent
//! requests deterministic: they cannot all pass the same free memory.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::phys;
use moto_sys::ErrorCode;

/// Which floor an operation must stay above. Only sys-io's address space is
/// privileged; everything else, including sys-init, is ordinary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemClass {
    User,
    SysIo,
}

// The floors are compile-time safety constants, sized for VM-scale machines
// (2026-08-06 review; earlier revisions derived them from total RAM at
// boot). Patch 3 validates them under measured load. A machine whose
// small-page pool is not comfortably above PRESSURE_HIGH_PAGES cannot run
// with these constants.
pub const USER_FLOOR_PAGES: u64 = 4096; // 16M.
pub const SYS_IO_FLOOR_PAGES: u64 = 1024; // 4M.

// The memory-pressure watermarks. While free-for-admission is at or below
// the low one, the kernel keeps the `memory_pressure` flag in
// `KernelStaticPage` raised; userspace (sys-io, the process runtime) fails
// new memory-growing work fast without a syscall. The gap between them is
// hysteresis: one allocation or free cannot flip service off and on
// repeatedly. Both sit well above the user floor, so pressure begins long
// before anything is refused admission.
pub const PRESSURE_LOW_PAGES: u64 = 2 * USER_FLOOR_PAGES; // 32M.
pub const PRESSURE_HIGH_PAGES: u64 = 3 * USER_FLOOR_PAGES; // 48M.

/// Pages reserved by admitted operations that have not completed yet.
static RESERVED_PAGES: AtomicU64 = AtomicU64::new(0);
/// The lowest number of free small pages ever observed at an admission check.
static LOW_WATER_PAGES: AtomicU64 = AtomicU64::new(u64::MAX);

pub static REFUSED_USER: AtomicU64 = AtomicU64::new(0);
pub static REFUSED_SYS_IO: AtomicU64 = AtomicU64::new(0);

pub fn reserved_pages() -> u64 {
    RESERVED_PAGES.load(Ordering::Relaxed)
}

/// The shared-page flag itself -- the only pressure state there is. `None`
/// during early boot, before the kernel address space exists; transitions
/// cannot happen then anyway, since admission only runs for userspace.
fn pressure_flag() -> Option<&'static AtomicU32> {
    if !super::virt::KERNEL_ADDRESS_SPACE.is_set() {
        return None;
    }
    Some(&super::virt::get_kernel_static_page_mut().memory_pressure)
}

/// Maintain the shared-page pressure flag from the quantity admission
/// compares against floors. The CAS picks a single transition winner, so the
/// flag is written once per transition, not once per caller.
fn update_pressure(free_for_admission: u64) {
    let Some(flag) = pressure_flag() else {
        return;
    };
    if flag.load(Ordering::Relaxed) != 0 {
        if free_for_admission >= PRESSURE_HIGH_PAGES {
            let _ = flag.compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed);
        }
    } else if free_for_admission <= PRESSURE_LOW_PAGES {
        let _ = flag.compare_exchange(0, 1, Ordering::Release, Ordering::Relaxed);
    }
}

/// Called from the small-page free path, so the flag clears when memory is
/// freed outside any admission window -- a dying process's teardown, an
/// unmap. Gated: one load per free while the flag is down.
pub fn note_pages_freed() {
    let Some(flag) = pressure_flag() else {
        return;
    };
    if flag.load(Ordering::Relaxed) != 0 {
        update_pressure(phys::available_small_pages().saturating_sub(reserved_pages()));
    }
}

/// `u64::MAX` until the first admission check.
pub fn low_water_pages() -> u64 {
    LOW_WATER_PAGES.load(Ordering::Relaxed)
}

/// An admitted reservation, released on drop. The pages the operation actually
/// allocated stay accounted by the physical allocator, so releasing the
/// reservation does not make consumed memory reappear as free.
pub struct Admission {
    pages: u64,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let reserved = RESERVED_PAGES.fetch_sub(self.pages, Ordering::AcqRel) - self.pages;
        update_pressure(phys::available_small_pages().saturating_sub(reserved));
    }
}

/// Reserve `charge_pages` small pages for a memory-growing operation on an
/// address space of class `class`, or refuse with `E_OUT_OF_MEMORY`.
///
/// The reservation is held for the whole operation, which double-counts the
/// pages the operation has already allocated. That can refuse another request
/// early, but cannot admit too much.
pub fn admit(class: MemClass, charge_pages: u64) -> Result<Admission, ErrorCode> {
    let floor = match class {
        MemClass::User => USER_FLOOR_PAGES,
        MemClass::SysIo => SYS_IO_FLOOR_PAGES,
    };

    let mut reserved = RESERVED_PAGES.load(Ordering::Relaxed);
    loop {
        let available = phys::available_small_pages();
        record_low_water(available);

        let free = available.saturating_sub(reserved);
        update_pressure(free);
        if free < charge_pages || (free - charge_pages) < floor {
            return Err(refuse(class));
        }

        match RESERVED_PAGES.compare_exchange_weak(
            reserved,
            reserved + charge_pages,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => reserved = actual,
        }
    }
    let admission = Admission {
        pages: charge_pages,
    };

    // The check and the reservation above are two steps, not one. Between
    // reading `available` and winning the CAS, other operations can admit,
    // allocate, and release, restoring the counter to the compared value while
    // the availability just checked is stale -- a window a host vCPU deschedule
    // stretches arbitrarily. Re-verify with the reservation published. The
    // counter is read first (Acquire, pairing with the release in Drop), so
    // the allocations of operations that already released are visible in
    // `available` below, and operations still in flight have their full charge
    // counted in `reserved`. The re-check can doubly refuse racing requests
    // near the floor; it cannot admit too much.
    let reserved = RESERVED_PAGES.load(Ordering::Acquire);
    let available = phys::available_small_pages();
    record_low_water(available);
    // `reserved` includes this operation's own charge.
    let free = available.saturating_sub(reserved);
    update_pressure(free);
    if free < floor {
        core::mem::drop(admission);
        return Err(refuse(class));
    }

    Ok(admission)
}

fn refuse(class: MemClass) -> ErrorCode {
    match class {
        MemClass::User => REFUSED_USER.fetch_add(1, Ordering::Relaxed),
        MemClass::SysIo => REFUSED_SYS_IO.fetch_add(1, Ordering::Relaxed),
    };
    moto_rt::E_OUT_OF_MEMORY
}

fn record_low_water(available: u64) {
    let mut low = LOW_WATER_PAGES.load(Ordering::Relaxed);
    while available < low {
        match LOW_WATER_PAGES.compare_exchange_weak(
            low,
            available,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => low = actual,
        }
    }
}

// Allocating N data pages also grows page descriptors, page tables and the
// global frame slab. Admission charges one page per METADATA_DIVISOR pages
// touched, i.e. PAGE_SIZE_SMALL / METADATA_DIVISOR == 128 bytes per page.
// Measured worst case is ~104 bytes: 73 for a struct Page slab entry (see
// virt_intrusive), 21 for a struct Frame entry (see phys), 8 for page tables.
const METADATA_DIVISOR: u64 = 32;
/// Covers unfavorable slab and page-table boundaries, where a single extra
/// page can pull in a whole new slab.
const METADATA_FLAT_PAGES: u64 = 64;

/// The number of bytes of metadata growth per touched page that
/// `METADATA_DIVISOR` buys. Structure-size assertions elsewhere in `mm` keep
/// the real cost below it.
pub const METADATA_BYTES_PER_PAGE: usize =
    (super::PAGE_SIZE_SMALL as usize) / (METADATA_DIVISOR as usize);

/// Conservative charge for a mapping that adds `data_pages` physical small
/// pages and `descriptor_pages` page descriptors. A shared mapping counts
/// descriptors at both ends. Saturating: a nonsense request is refused, not
/// wrapped into a small charge.
pub fn mapping_charge(data_pages: u64, descriptor_pages: u64) -> u64 {
    data_pages
        .saturating_add(
            data_pages
                .saturating_add(descriptor_pages)
                .div_ceil(METADATA_DIVISOR),
        )
        .saturating_add(METADATA_FLAT_PAGES)
}

/// Charge for one lazy page fault: a single data page and its metadata.
pub fn lazy_fault_charge() -> u64 {
    mapping_charge(1, 0)
}

// Fixed charges for the non-mapping operations. Starting points; they are
// raised if boundary tests ever exceed them.
pub const PROCESS_CHARGE_PAGES: u64 = 256; // 1M.
pub const THREAD_CHARGE_PAGES: u64 = 64; // 256K.
pub const OBJECT_CHARGE_PAGES: u64 = 16; // 64K.
