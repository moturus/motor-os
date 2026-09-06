extern crate alloc;

#[path = "../sys/kernel/src/util/inline_vec.rs"]
mod inline_vec;
use inline_vec::InlineVec;

fn wakers(values: &[u64]) -> InlineVec<u64, 4> {
    let mut result = InlineVec::new(0);
    for value in values {
        result.push(*value);
    }
    result.sort_dedup();
    result
}

#[test]
fn unrelated_wait_does_not_select_pending_notifications() {
    let queued = wakers(&[7, 3, 5]);
    assert!(queued.intersection([].into_iter()).is_empty());
    assert!(queued.intersection([0, 9].into_iter()).is_empty());
    assert_eq!(queued.as_slice(), &[3, 5, 7]);
}

#[test]
fn shrinking_wait_selects_only_requested_handles_once() {
    let queued = wakers(&[7, 3, 5, 3]);
    let selected = queued.intersection([7, 0, 3, 7, 99].into_iter());
    assert_eq!(selected.len(), 2);
    assert_eq!(selected.as_slice(), &[3, 7]);
    assert!(wakers(&[]).intersection([3].into_iter()).is_empty());
}

#[test]
fn spilled_wakers_and_requests_are_filtered() {
    let queued = wakers(&(1..=32).rev().collect::<Vec<_>>());
    let selected = queued.intersection((0..=64).rev().filter(|v| v % 2 == 0));
    assert_eq!(
        selected.as_slice(),
        &(2..=32).step_by(2).collect::<Vec<_>>()
    );
    assert_eq!(queued.intersection([31].into_iter()).as_slice(), &[31]);
}
