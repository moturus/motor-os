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

// Count of shootdown waits that crossed the 1e9-spin "slow" mark below -- a
// peer vCPU the host descheduled long enough to notice. Exposed as the
// cpu.tlb_shootdown_slow system metric (see xray::stats).
pub static TLB_SHOOTDOWN_SLOW_COUNT: AtomicU64 = AtomicU64::new(0);

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

// num_pages sentinel: the message is not a range invalidation but a page
// table eviction — see evict_user_page_table().
pub(super) const EVICT_PAGE_TABLE: u64 = u64::MAX;

// W6b: syscalls and preempts no longer switch CR3, so a CPU's sched loop
// can idle on the page table of a parked (or dead) thread's process. Before
// a user page table's L4 page is freed, every CPU still running on it must
// be moved off — otherwise the hardware page walker would read freed and
// reused memory as page tables. Broadcasts to all CPUs; each switches to
// the kernel page table iff its current CR3 matches.
pub fn evict_user_page_table(page_table: u64) {
    invalidate(page_table, 0, EVICT_PAGE_TABLE)
}

pub fn invalidate(page_table: u64, first_page_vaddr: u64, num_pages: u64) {
    crate::xray::tracing::trace(
        "tlb::invalidate: will lock",
        page_table,
        first_page_vaddr,
        num_pages,
    );
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
    let mut noted_slow = false;
    while MESSAGE.cpumask.load(Ordering::Relaxed) != done_mask {
        counter += 1;
        // A shootdown almost never spins this long for a real reason. Under a
        // hypervisor a peer vCPU can be descheduled by the host for many ms
        // (the guest IF flag has no bearing on host scheduling), so it cannot
        // ack the IPI until the host reschedules it -- at which point it
        // recovers on its own. Wait very patiently (1e11 spins, tens of
        // seconds to minutes) before treating a stall as a true all-CPU wedge;
        // a real hang is caught far sooner by higher-level liveness checks.
        // Note the first 1e9-spin crossing once, for the operator and the
        // cpu.tlb_shootdown_slow metric.
        if counter == 1_000_000_000 && !noted_slow {
            noted_slow = true;
            TLB_SHOOTDOWN_SLOW_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::write_serial!(
                "\nTLB shootdown slow on cpu {this_cpu}: 1e9 spins, still waiting for cpu mask 0b{:b} (likely host vCPU preemption)\n",
                done_mask & !MESSAGE.cpumask.load(Ordering::Acquire)
            );
        }
        if counter > 100_000_000_000 {
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
    if num_pages == EVICT_PAGE_TABLE {
        super::paging::evict_if_current(page_table);
    } else {
        super::paging::invalidate(page_table, first_page_vaddr, num_pages);
    }

    // Signal that we got the message.
    MESSAGE
        .cpumask
        .fetch_or(1_u64 << this_cpu, Ordering::SeqCst);
}
