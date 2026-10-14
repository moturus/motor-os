extern crate alloc;
extern crate self as moto_rt;
extern crate self as moto_sys;

pub type ErrorCode = u16;
pub const E_INVALID_ARGUMENT: ErrorCode = 1;

mod config {
    #[allow(non_camel_case_types)]
    pub type uCpus = u8;
}
mod mm {
    pub const PAGE_SIZE_SMALL: u64 = 4096;
    pub mod admission {
        pub struct Commitment(pub u64);
    }
    pub mod user {
        pub struct UserAddressSpace;
    }
}
mod uspace {
    pub mod process {
        pub struct Thread(pub u64);
    }
}

#[path = "../sys/kernel/src/uspace/pager/mapping.rs"]
mod mapping;

use mapping::{Mapping, Waiter};
use mm::PAGE_SIZE_SMALL as PAGE;
use std::sync::{Arc, Weak};

const START: u64 = 2 * PAGE;
const END: u64 = START + 3 * PAGE;

fn mapping() -> (Mapping, Vec<Arc<uspace::process::Thread>>) {
    let threads: Vec<_> = (0..6)
        .map(|id| Arc::new(uspace::process::Thread(id)))
        .collect();
    let waiters = threads
        .iter()
        .enumerate()
        .map(|(idx, thread)| Waiter {
            page: START + (idx as u64 / 2) * PAGE,
            thread: Arc::downgrade(thread),
            cpu: idx as u8,
        })
        .collect();
    (
        Mapping {
            space: Weak::new(),
            reservation: mm::admission::Commitment(3),
            start: START,
            end: END,
            zero_from: u64::MAX,
            queued: (0..3).map(|idx| START + idx * PAGE).collect(),
            waiters,
        },
        threads,
    )
}

fn waiters(waiters: &[Waiter]) -> Vec<(u64, u64, u8)> {
    waiters
        .iter()
        .map(|w| (w.page, w.thread.upgrade().unwrap().0, w.cpu))
        .collect()
}

#[test]
fn invalid_failure_pages_leave_mapping_unchanged() {
    let (mut mapping, _threads) = mapping();
    let queued = mapping.queued.clone();
    let pending = waiters(&mapping.waiters);
    for page in [
        u64::MAX,               // Retirement marker, not a page.
        u64::MAX & !(PAGE - 1), // Aligned, but its end overflows.
        START - PAGE,
        START - 1,
        START + 1,
        END - 1,
        END,
        END + PAGE,
    ] {
        assert!(
            matches!(mapping.fail_page(page), Err(E_INVALID_ARGUMENT)),
            "{page:#x}"
        );
        assert_eq!(mapping.queued, queued);
        assert_eq!(waiters(&mapping.waiters), pending);
        assert_eq!(
            (mapping.start, mapping.end, mapping.zero_from),
            (START, END, u64::MAX)
        );
        assert_eq!(mapping.reservation.0, 3);
        assert_eq!(mapping.space.strong_count(), 0);
    }
}

#[test]
fn valid_failure_selects_only_the_requested_page() {
    let (mut mapping, threads) = mapping();
    let first = mapping.fail_page(START).unwrap();
    assert_eq!(waiters(&first), [(START, 0, 0), (START, 1, 1)]);
    let last = mapping.fail_page(END - PAGE).unwrap();
    assert_eq!(waiters(&last), [(END - PAGE, 4, 4), (END - PAGE, 5, 5)]);
    assert_eq!(
        waiters(&mapping.waiters),
        [(START + PAGE, 2, 2), (START + PAGE, 3, 3)]
    );
    assert_eq!(
        mapping.queued.iter().copied().collect::<Vec<_>>(),
        [START + PAGE]
    );
    assert!(mapping.fail_page(START).unwrap().is_empty());
    assert_eq!(mapping.reservation.0, 3); // Failure does not release admission.
    assert!(threads.iter().all(|thread| Arc::weak_count(thread) == 1));
}

#[test]
fn fill_range_takes_each_waiter_once_and_keeps_the_endpoint() {
    let (mut mapping, _threads) = mapping();
    let ready = mapping.take_waiters(START, END - PAGE);
    assert_eq!(
        waiters(&ready).iter().map(|w| w.1).collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(
        waiters(&mapping.waiters),
        [(END - PAGE, 4, 4), (END - PAGE, 5, 5)]
    );
    assert_eq!(
        mapping.queued.iter().copied().collect::<Vec<_>>(),
        [END - PAGE]
    );
    assert!(mapping.take_waiters(START, END - PAGE).is_empty());
}
