// TLB shootdown.

use core::{ops::Deref, sync::atomic::*};

use alloc::vec::Vec;

use crate::util::{SpinLock, StaticRef};

#[derive(Default)]
struct TlbShootdownMessage {
    page_table: AtomicU64,
    first_page_vaddr: AtomicU64,
    num_pages: AtomicU64,
    cpumask: AtomicU64,
    generation: AtomicU64,
    done_mask: AtomicU64,
    shootdown_count: AtomicU64,
    lock: SpinLock<()>,
}

// We use u64 as cpumask, so we don't support more than 64 CPUs.
const _: () = assert!(crate::config::MAX_CPUS <= 64);

static MESSAGE: StaticRef<TlbShootdownMessage> = StaticRef::default_const();
static PERCPU_PROCESSED_GENERATION: StaticRef<Vec<AtomicU64>> = StaticRef::default_const();

pub fn setup() {
    use alloc::boxed::Box;

    let num_cpus = crate::arch::num_cpus();
    MESSAGE.set(Box::leak(Box::new(TlbShootdownMessage::default())));
    MESSAGE
        .done_mask
        .store((1_u64 << num_cpus) - 1, Ordering::Release);

    let mut vec = Vec::with_capacity(num_cpus as usize);
    for _ in 0..num_cpus {
        vec.push(AtomicU64::new(0));
    }

    PERCPU_PROCESSED_GENERATION.set(Box::leak(Box::new(vec)));
}

pub fn invalidate(page_table: u64, first_page_vaddr: u64, num_pages: u64) {
    crate::xray::tracing::trace("tlb::invalidate: will lock", 0, 0, 0);
    let _lock = MESSAGE.lock.lock(line!());

    MESSAGE.page_table.store(page_table, Ordering::Relaxed);
    MESSAGE
        .first_page_vaddr
        .store(first_page_vaddr, Ordering::Relaxed);
    MESSAGE.num_pages.store(num_pages, Ordering::Relaxed);
    MESSAGE.generation.fetch_add(1, Ordering::SeqCst);

    debug_assert_eq!(0, MESSAGE.cpumask.load(Ordering::Relaxed));

    let num_cpus = crate::arch::num_cpus();
    let this_cpu = crate::arch::current_cpu();
    for cpu in 0..num_cpus {
        if cpu != this_cpu {
            super::irq::shoot_remote_tlb(cpu);
        }
    }

    shoot_from_irq(); // Invalidate for the current CPU.

    let done_mask = MESSAGE.done_mask.load(Ordering::Acquire);
    let mut counter: u64 = 0;
    while MESSAGE.cpumask.load(Ordering::Relaxed) != done_mask {
        counter += 1;
        if counter > 1_000_000 {
            panic!(
                "\nTLB shootdown hung: this cpu: {this_cpu}, mask: 0b{:b}",
                MESSAGE.cpumask.load(Ordering::Acquire)
            );
        }
        core::hint::spin_loop();
    }

    MESSAGE.cpumask.store(0, Ordering::Release);
    MESSAGE.shootdown_count.fetch_add(1, Ordering::Relaxed);
    crate::xray::tracing::trace("tlb::invalidate: done", 0, 0, 0);
}

pub(super) fn shoot_from_irq() {
    // NOTE: called from IRQ.
    let this_cpu = crate::arch::current_cpu();
    let local_generation =
        1 + PERCPU_PROCESSED_GENERATION.deref()[this_cpu as usize].fetch_add(1, Ordering::SeqCst);
    assert_eq!(local_generation, MESSAGE.generation.load(Ordering::Acquire));

    let page_table = MESSAGE.page_table.load(Ordering::Relaxed);
    let first_page_vaddr = MESSAGE.first_page_vaddr.load(Ordering::Relaxed);
    let num_pages = MESSAGE.num_pages.load(Ordering::Relaxed);

    // Do the work.
    super::paging::invalidate(page_table, first_page_vaddr, num_pages);

    // Signal that we got the message.
    MESSAGE
        .cpumask
        .fetch_or(1_u64 << this_cpu, Ordering::SeqCst);
}
