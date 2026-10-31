//! Physical-memory pressure publication, independent of allocation policy.

use core::sync::atomic::Ordering;

pub const LOW_PAGES: u64 = 512; // 2 MiB.
pub const HIGH_PAGES: u64 = 768; // 3 MiB.

pub fn active() -> bool {
    super::virt::get_kernel_static_page_mut()
        .memory_pressure
        .load(Ordering::Relaxed)
        != 0
}

fn next_pressure(free: u64, pressure: u32) -> u32 {
    if free < LOW_PAGES {
        1
    } else if free >= HIGH_PAGES {
        0
    } else {
        pressure
    }
}

pub fn update() {
    if !super::virt::KERNEL_ADDRESS_SPACE.is_set() {
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _guard = super::virt::KERNEL_ADDRESS_SPACE
            .pressure_update
            .lock(line!());
        let page = super::virt::get_kernel_static_page_mut();
        let free = super::phys::available_small_pages();
        page.free_pages.store(free, Ordering::Relaxed);
        let pressure = page.memory_pressure.load(Ordering::Relaxed);
        let next = next_pressure(free, pressure);
        if next != pressure {
            page.memory_pressure.store(next, Ordering::Release);
        }
    });
}

// Called only at quiescent boot-time checkpoints, before the APs start.
#[cfg(debug_assertions)]
pub(super) fn assert_snapshot() {
    assert_eq!(
        super::virt::get_kernel_static_page_mut()
            .free_pages
            .load(Ordering::Relaxed),
        super::phys::available_small_pages()
    );
}

#[cfg(debug_assertions)]
pub(super) fn self_test() {
    for pressure in [0, 1] {
        assert_eq!(next_pressure(511, pressure), 1);
        assert_eq!(next_pressure(512, pressure), pressure);
        assert_eq!(next_pressure(767, pressure), pressure);
        assert_eq!(next_pressure(768, pressure), 0);
    }
    assert_snapshot();
}
