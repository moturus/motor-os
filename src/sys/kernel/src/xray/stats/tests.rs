//! Runs inside the debug guest; never advances the live system PID counters.
use super::*;

pub(crate) fn run() {
    assert_eq!(system_stats_ref().kernel_pid(), PID_SYSTEM);
    assert_eq!(kernel_stats_ref().kernel_pid(), PID_KERNEL);
    let mut children = Children::default();
    for expected in PID_KERNEL + 1..10 {
        let (kernel_pid, user_pid) = allocate_pids_locked(&mut children).unwrap();
        assert_eq!((kernel_pid, user_pid.as_u64()), (expected, expected));
    }

    let mut children = Children {
        next_kernel_pid: PID_MAX - 1,
        next_user_pid: PID_MAX - 1,
        ..Children::default()
    };
    let old = allocate_pids_locked(&mut children).unwrap();
    let wrapped = allocate_pids_locked(&mut children).unwrap();
    assert_eq!((old.0, old.1.as_u64()), (PID_MAX - 1, PID_MAX - 1));
    assert_eq!((wrapped.0, wrapped.1.as_u64()), (PID_MAX, FIRST_WRAP_PID));
    // A reserved (not yet registered) user PID must be skipped too.
    children.next_user_pid = FIRST_WRAP_PID;
    let newest = allocate_pids_locked(&mut children).unwrap();
    assert_eq!(
        (newest.0, newest.1.as_u64()),
        (PID_MAX + 1, FIRST_WRAP_PID + 1)
    );
    assert_eq!(children.by_user_pid[&wrapped.1], wrapped.0);

    let live = Arc::downgrade(&kernel_stats());
    for weak in children.by_kernel_pid.values_mut() {
        *weak = live.clone();
    }
    let children = SpinLock::new(children);
    let mut kernel_order = alloc::vec::Vec::new();
    KProcessStats::for_each_child(&children, 0, line!(), |kernel_pid, child| {
        assert!(child.is_some());
        // Re-locking here verifies the callback runs outside the map lock.
        assert!(children
            .lock(line!())
            .by_kernel_pid
            .contains_key(&kernel_pid));
        kernel_order.push(kernel_pid);
        true
    });
    assert_eq!(kernel_order, [old.0, wrapped.0, newest.0]);
    assert_eq!(kernel_order.into_iter().max(), Some(newest.0));

    let mut public_order = alloc::vec::Vec::new();
    KProcessStats::for_each_user_child(&children, ProcessId::from_u64(0), |pid, child| {
        assert!(child.is_some());
        assert!(children.lock(line!()).by_user_pid.contains_key(&pid));
        public_order.push(pid);
        public_order.len() < 2
    });
    assert_eq!(public_order, [wrapped.1, newest.1]);
    let next = ProcessId::from_u64(public_order.last().unwrap().as_u64() + 1);
    KProcessStats::for_each_user_child(&children, next, |pid, _| {
        public_order.push(pid);
        true
    });
    assert_eq!(public_order, [wrapped.1, newest.1, old.1]);
    let mut inclusive = None;
    KProcessStats::for_each_user_child(&children, old.1, |pid, _| {
        inclusive = Some(pid);
        false
    });
    assert_eq!(inclusive, Some(old.1));

    {
        let mut entries = children.lock(line!());
        entries.by_kernel_pid.remove(&wrapped.0).unwrap();
        assert_eq!(entries.by_user_pid.remove(&wrapped.1), Some(wrapped.0));
        entries.next_user_pid = wrapped.1.as_u64();
        let reused = allocate_pids_locked(&mut entries).unwrap();
        assert_eq!(reused, (newest.0 + 1, wrapped.1));
        assert_eq!(entries.by_user_pid[&wrapped.1], reused.0);
        assert!(!entries.by_kernel_pid.contains_key(&wrapped.0));
    }

    let mut children = Children {
        next_kernel_pid: u64::MAX - 1,
        ..Children::default()
    };
    assert_eq!(allocate_pids_locked(&mut children).unwrap().0, u64::MAX - 1);
    assert!(allocate_pids_locked(&mut children).is_none());
    assert_eq!(children.next_kernel_pid, u64::MAX);
    crate::raw_log!("process PID tests PASS");
}
