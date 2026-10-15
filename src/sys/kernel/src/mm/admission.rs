//! Low-memory admission control.
//!
//! Userspace operations that grow physical memory must be admitted first.
//! Admission refuses them while a guard band of small pages is still free, so
//! the physical allocator never empties and panics the kernel. Charges are
//! conservative upper bounds, not exact bills, and are held as atomic
//! reservations for the duration of the operation, which makes concurrent
//! requests deterministic: they cannot all pass the same free memory.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::phys;
use crate::util::SpinLock;
use crate::xray::stats::{self, MetricType};
use moto_sys::{ErrorCode, KernelStaticPage};

/// Which floor an operation must stay above. CAP_SYS and CAP_IO_MANAGER
/// address spaces may use the reserve; ordinary processes may not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemClass {
    User,
    Privileged,
}

// The floors are compile-time safety constants. The lower floor and its
// exported stats retain their historical sys-io names.
pub const USER_FLOOR_PAGES: u64 = 256; // 1M.
pub const SYS_IO_FLOOR_PAGES: u64 = 128; // 512K.

// The memory-pressure watermarks. While free-for-admission is at or below
// the low one, the kernel keeps the `memory_pressure` flag in
// `KernelStaticPage` raised; userspace (sys-io, the process runtime) fails
// new memory-growing work fast without a syscall. The gap between them is
// hysteresis: one allocation or free cannot flip service off and on
// repeatedly. Both sit well above the user floor, so pressure begins long
// before anything is refused admission.
pub const PRESSURE_LOW_PAGES: u64 = 2 * USER_FLOOR_PAGES; // 2M.
pub const PRESSURE_HIGH_PAGES: u64 = 3 * USER_FLOOR_PAGES; // 3M.

// Serializes sampling and publication, including frees while pressure is down.
static PRESSURE_UPDATE: SpinLock<()> = SpinLock::new(());

/// Admission's two "taken but not allocated" counters live on the shared
/// static page beside the pressure flag: pages reserved by admitted operations
/// that have not completed yet, and pages committed to demand-paged executable
/// images and not yet filled (counted like reservations, so a running
/// executable's own pages are never refused; see `commit`). `None` during
/// early boot, before the kernel address space exists, like the flag.
fn page_counter(
    pick: fn(&'static KernelStaticPage) -> &'static AtomicU64,
) -> Option<&'static AtomicU64> {
    if !super::virt::KERNEL_ADDRESS_SPACE.is_set() {
        return None;
    }
    Some(pick(super::virt::get_kernel_static_page_mut()))
}

fn reserved() -> Option<&'static AtomicU64> {
    page_counter(|page| &page.reserved_pages)
}

fn committed() -> Option<&'static AtomicU64> {
    page_counter(|page| &page.committed_pages)
}

fn load(counter: Option<&AtomicU64>, order: Ordering) -> u64 {
    counter.map_or(0, |counter| counter.load(order))
}

/// Admissions and commitments are only ever taken from userspace, so the page
/// exists by then.
fn live(counter: Option<&'static AtomicU64>) -> &'static AtomicU64 {
    counter.expect("admission before the kernel address space")
}

pub fn reserved_pages() -> u64 {
    load(reserved(), Ordering::Relaxed)
}

pub fn committed_pages() -> u64 {
    load(committed(), Ordering::Relaxed)
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

/// Sample inside the publication lock: an old observation must not overwrite
/// a newer completed update. Counter changes racing with this sample have
/// their own update, which cannot complete until this publisher releases.
fn update_pressure() {
    let Some(flag) = pressure_flag() else {
        return;
    };
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _guard = PRESSURE_UPDATE.lock(line!());
        let reserved = load(reserved(), Ordering::Acquire) + load(committed(), Ordering::Acquire);
        let free = phys::available_small_pages().saturating_sub(reserved);
        let pressure = flag.load(Ordering::Relaxed);
        let next = if free <= PRESSURE_LOW_PAGES {
            1
        } else if free >= PRESSURE_HIGH_PAGES {
            0
        } else {
            pressure
        };
        if next != pressure {
            flag.store(next, Ordering::Release);
        }
    });
}

/// How many times the free path has notified admission; a debug test oracle.
#[cfg(debug_assertions)]
pub fn free_notifications() -> u64 {
    stats::admission_free_notifications()
}

/// Frees outside admission windows must publish too. Skipping a clear flag
/// would let a concurrent publisher raise pressure after recovery unnoticed.
pub fn note_pages_freed() {
    #[cfg(debug_assertions)]
    stats::note_admission_free_notification();
    update_pressure();
}

/// An admitted reservation, released on drop. The pages the operation actually
/// allocated stay accounted by the physical allocator, so releasing the
/// reservation does not make consumed memory reappear as free.
pub struct Admission {
    pages: u64,
}

impl Drop for Admission {
    fn drop(&mut self) {
        live(reserved()).fetch_sub(self.pages, Ordering::AcqRel);
        update_pressure();
    }
}

/// A standing commitment of pages to a demand-paged image, released page
/// by page as the pages are filled, and in full on drop.
pub struct Commitment {
    pages: u64,
}

impl Commitment {
    /// Gives back up to `pages`, as the pages it was held for are allocated.
    pub fn release(&mut self, pages: u64) {
        let pages = pages.min(self.pages);
        if pages != 0 {
            self.pages -= pages;
            live(committed()).fetch_sub(pages, Ordering::AcqRel);
            update_pressure();
        }
    }
}

impl Drop for Commitment {
    fn drop(&mut self) {
        live(committed()).fetch_sub(self.pages, Ordering::AcqRel);
        update_pressure();
    }
}

/// Admits `charge_pages` like `admit`, then holds them as a commitment that
/// outlives the operation.
pub fn commit(class: MemClass, charge_pages: u64) -> Result<Commitment, ErrorCode> {
    let admission = admit(class, charge_pages)?;
    // Counted as committed before the transient reservation goes.
    live(committed()).fetch_add(charge_pages, Ordering::AcqRel);
    drop(admission);
    Ok(Commitment {
        pages: charge_pages,
    })
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
        MemClass::Privileged => SYS_IO_FLOOR_PAGES,
    };

    let reserved_pages = live(reserved());
    let mut reserved = reserved_pages.load(Ordering::Relaxed);
    loop {
        let available = phys::available_small_pages();
        stats::record_admission_low_water(available);

        let committed = load(committed(), Ordering::Relaxed);
        let free = available.saturating_sub(reserved + committed);
        update_pressure();
        if free < charge_pages || (free - charge_pages) < floor {
            return Err(refuse(class));
        }

        match reserved_pages.compare_exchange_weak(
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
    let reserved = reserved_pages.load(Ordering::Acquire) + load(committed(), Ordering::Acquire);
    let available = phys::available_small_pages();
    stats::record_admission_low_water(available);
    // `reserved` includes this operation's own charge.
    let free = available.saturating_sub(reserved);
    update_pressure();
    if free < floor {
        core::mem::drop(admission);
        return Err(refuse(class));
    }

    Ok(admission)
}

fn refuse(class: MemClass) -> ErrorCode {
    let metric = match class {
        MemClass::User => MetricType::AdmissionRefusedUser,
        MemClass::Privileged => MetricType::AdmissionRefusedSysIo,
    };
    stats::kernel_stats_ref().adjust_metric(metric, 1);
    moto_rt::E_OUT_OF_MEMORY
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
