use super::*;
use crate::mm::phys_blocks::tests::{check, Fixture, HIGH};

fn boundaries() {
    use AllocationClass::*;
    use RefusalKind::*;
    let total = 2048;
    for class in [Kernel, System, User] {
        let (next, refusal) = StateSnapshot::new(total - 1).charge(total, 1, class);
        assert_eq!(refusal, None);
        assert_eq!(next, StateSnapshot::new(total));
    }
    // Inclusive floors and recovery, including huge-page refusal above recovery.
    for (free, count, class, refusal, phase, blocked) in [
        (513, 1, User, None, IDLE, false),
        (512, 1, User, Some(Floor), KILLING, false),
        (511, 1, User, Some(Floor), KILLING, false),
        (768, 512, User, Some(Floor), IDLE, false),
        (767, 512, User, Some(Floor), KILLING, false),
        (129, 1, System, None, KILLING, false),
        (128, 1, System, Some(Floor), KILLING, true),
        (127, 1, System, Some(Floor), KILLING, true),
        (512, 1, Kernel, None, KILLING, false),
        (128, 1, Kernel, None, KILLING, true),
        (1, 1, Kernel, None, KILLING, true),
        (0, 1, Kernel, Some(Capacity), IDLE, false),
    ] {
        let old = StateSnapshot(StateSnapshot::new(total - free).0 | ARMED);
        let (next, actual) = old.charge(total, count, class);
        assert_eq!(actual, refusal);
        assert_eq!(
            next.used(),
            old.used()
                + if refusal.is_none() {
                    u64::from(count)
                } else {
                    0
                }
        );
        assert_eq!(next.phase(), phase);
        assert_eq!(next.0 & SYSTEM_BLOCKED != 0, blocked);
        assert_eq!(next.0 / GENERATION_ONE, u64::from(phase == KILLING));
    }
    for phase in [KILLING, LATCHED] {
        for blocked in [0, SYSTEM_BLOCKED] {
            let old = StateSnapshot(ARMED | phase | blocked | GENERATION_ONE | (total - 767));
            for class in [Kernel, System, User] {
                let (_, refusal) = old.charge(total, 1, class);
                assert_eq!(
                    refusal,
                    if class == User || (class == System && blocked != 0) {
                        Some(Gate)
                    } else {
                        None
                    }
                );
            }
            let recovered = old.release(total, 1);
            assert_eq!(
                recovered,
                StateSnapshot(ARMED | (2 * GENERATION_ONE) | (total - 768))
            );
            let (pressured, _) = recovered.charge(total, 257, Kernel);
            assert_eq!(pressured.phase(), KILLING);
            assert_eq!(pressured.0 / GENERATION_ONE, 3);
            assert_eq!(old.release(total, 0), old);
        }
    }
    let latched = StateSnapshot(ARMED | LATCHED | GENERATION_ONE | (total - 512));
    assert_eq!(latched.charge(total, 385, System), (latched, Some(Floor)));
    let (restart, _) = latched.charge(total, 1, System);
    assert_eq!(restart.phase(), KILLING);
    assert_eq!(restart.0 / GENERATION_ONE, 2);
    assert_eq!(StateSnapshot(!(GENERATION_ONE - 1)).next_generation(), None);
    assert_eq!(
        StateSnapshot::new(MAX_BLOCKS as u64 * u64::from(PAGES)).used(),
        1 << 24
    );
}

fn ownership_and_recovery() {
    use AllocationClass::*;
    let mut fixture = Fixture::new();
    for index in [0, HIGH, HIGH + 1] {
        fixture.shape(index, 0, PAGES);
    }
    let pool = fixture.pool();
    pool.counters.state.store(ARMED, Ordering::Release);
    let huge = pool.allocate_huge(User).unwrap().unwrap();
    let run = pool.allocate(512, None, User).unwrap().unwrap();
    check(&pool, 1024);
    let before = pool.counters.splits.load(Ordering::Relaxed);
    assert!(matches!(
        pool.allocate(1, None, User),
        Err(AllocationError::Refused {
            kind: RefusalKind::Floor,
            ..
        })
    ));
    assert_eq!(pool.counters.splits.load(Ordering::Relaxed), before);
    check(&pool, 1024);
    assert!(matches!(
        pool.allocate_huge(User),
        Err(AllocationError::Refused {
            kind: RefusalKind::Gate,
            ..
        })
    ));
    let system = pool.allocate(384, None, System).unwrap().unwrap();
    assert!(matches!(
        pool.allocate(1, None, System),
        Err(AllocationError::Refused {
            kind: RefusalKind::Floor,
            ..
        })
    ));
    check(&pool, 1408);
    pool.push(system).unwrap();
    assert!(matches!(
        pool.allocate(1, None, System),
        Err(AllocationError::Refused {
            kind: RefusalKind::Gate,
            ..
        })
    ));
    pool.return_huge(huge).unwrap();
    for page in 0..126 {
        pool.push(run + page * 4096).unwrap();
    }
    assert_eq!(pool.counters.total - pool.state_snapshot().used(), 767);
    assert_ne!(pool.state_snapshot().0 & SYSTEM_BLOCKED, 0);
    pool.push(run + 126 * 4096).unwrap();
    assert_eq!(
        pool.state_snapshot(),
        StateSnapshot(ARMED | (2 * GENERATION_ONE) | 768)
    );
    check(&pool, 768);
    pool.allocate_huge(Kernel).unwrap().unwrap();
    assert_eq!(pool.state_snapshot().0 / GENERATION_ONE, 3);
    for _ in 0..256 {
        pool.allocate(1, None, Kernel).unwrap().unwrap();
    }
    assert_ne!(pool.state_snapshot().0 & SYSTEM_BLOCKED, 0);
    assert_eq!(pool.allocate(1, None, Kernel), Ok(None));
    check(&pool, 1536);
}

fn stale_charge_and_rejected_whole() {
    use AllocationClass::*;
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    let pool = fixture.pool();
    pool.counters.state.store(ARMED, Ordering::Release);
    assert!(matches!(
        pool.take_huge(HIGH, User),
        Err(AllocationError::Refused {
            kind: RefusalKind::Floor,
            ..
        })
    ));
    assert_eq!(
        pool.block(HIGH).unwrap().state.load(Ordering::Relaxed),
        WHOLE
    );
    assert_eq!(pool.counters.high_water.load(Ordering::Relaxed), 0);
    check(&pool, 0);
    pool.allocate(383, None, System).unwrap().unwrap();
    let stale = pool.state_snapshot(); // 129 free: two callers each see room for one.
    let (candidate, refusal) = stale.charge(pool.counters.total, 1, System);
    assert_eq!(refusal, None);
    pool.allocate(1, None, System).unwrap().unwrap();
    assert_eq!(
        pool.counters.state.compare_exchange(
            stale.0,
            candidate.0,
            Ordering::AcqRel,
            Ordering::Acquire
        ),
        Err(candidate.0)
    );
    assert!(matches!(
        pool.allocate(1, None, System),
        Err(AllocationError::Refused {
            kind: RefusalKind::Floor,
            ..
        })
    ));
    check(&pool, 384);
    let old = pool.state_snapshot();
    assert_eq!(pool.take_huge(HIGH, Kernel), Ok(None));
    assert_eq!(pool.state_snapshot(), old); // An unsuccessful block search charges nothing.
}

pub(crate) fn run() {
    boundaries();
    ownership_and_recovery();
    stale_charge_and_rejected_whole();
    pressure_receipts();
    worker_transitions();
    crate::raw_log!("phys_blocks policy tests PASS");
}

fn worker_transitions() {
    use AllocationClass::Kernel;
    let mut fixture = Fixture::new();
    fixture.shape(0, 0, PAGES);
    fixture.shape(HIGH, 0, PAGES);
    let pool = fixture.pool();
    pool.request_oom_attention();
    assert!(!pool.take_oom_attention());
    assert!(!pool.still_killing(0));
    assert_eq!(pool.request_oom(), None);
    assert_eq!(pool.oom_runs(), 0);
    pool.counters.state.store(ARMED, Ordering::Release);
    assert_eq!(pool.request_oom(), None); // Recovery wins over a stale request.
    let first = pool.allocate(257, None, Kernel).unwrap().unwrap();
    assert_eq!(pool.request_oom(), Some(1)); // Actual shortage at 767 pages.
    assert!(pool.take_oom_attention());
    assert!(!pool.take_oom_attention());
    let running_generation = pool.state_snapshot().generation();
    assert!(pool.still_killing(running_generation));
    assert!(!pool.latch_oom(0));
    assert!(pool.latch_oom(1));
    assert!(!pool.still_killing(running_generation));
    assert!(!pool.still_killing(2));
    assert!(pool.take_oom_attention());
    assert_eq!(pool.request_oom(), Some(2)); // Joining Latched never restarts.
    assert!(!pool.take_oom_attention());
    assert_eq!(pool.oom_runs(), 1);
    pool.allocate(256, None, Kernel).unwrap().unwrap();
    let before_recovery = pool.state_snapshot();
    assert_eq!(before_recovery.generation(), 3);
    assert!(!pool.still_killing(running_generation));
    assert!(!pool.latch_oom(3)); // At 511 the victimless rule is abort, not latch.
    assert!(pool.take_oom_attention());

    // System activity changes the count without cancelling a kill/abort check
    // for this generation. Joining it needs no transition or extra attention.
    let page = pool
        .allocate(1, None, AllocationClass::System)
        .unwrap()
        .unwrap();
    assert_eq!(pool.state_snapshot().free_pages(1024), 510);
    assert!(pool.still_killing(3));
    assert_eq!(pool.request_oom(), Some(3));
    pool.push(page).unwrap();
    assert_eq!(pool.state_snapshot().free_pages(1024), 511);
    assert!(pool.still_killing(3));
    assert!(!pool.take_oom_attention());

    // Reaching 512 cancels the abort decision but does not end Killing: the
    // post-report check must sample both the generation and the current count.
    pool.push(first).unwrap();
    assert_eq!(pool.state_snapshot().free_pages(1024), 512);
    assert!(pool.still_killing(3));
    for page in 1..257 {
        pool.push(first + page * 4096).unwrap();
    }
    assert_eq!(pool.state_snapshot().generation(), 4);
    assert!(!pool.still_killing(3));
    assert_eq!(pool.request_oom(), None);
    pool.allocate(257, None, Kernel).unwrap().unwrap();
    let renewed = pool.state_snapshot();
    // Same count and phase, but recovery/new pressure without a dispatch must
    // invalidate the old kill, and count BOTH starts despite coalesced attention.
    assert_eq!(renewed.used(), before_recovery.used());
    assert_eq!(renewed.generation(), 5);
    assert!(!pool.still_killing(before_recovery.generation()));
    assert!(pool.still_killing(renewed.generation()));
    assert_eq!(pool.oom_runs(), 3);
    assert!(pool.take_oom_attention());
    assert!(!pool.take_oom_attention());
    check(&pool, 513);
    for free in [512, 767] {
        let state =
            StateSnapshot(ARMED | KILLING | SYSTEM_BLOCKED | GENERATION_ONE | (2048 - free));
        let stopped = state.latch(2048, 1).unwrap();
        assert_eq!(stopped.phase(), LATCHED);
        assert_eq!(stopped.0 & SYSTEM_BLOCKED, 0);
        assert_eq!(stopped.generation(), 2);
        assert_eq!(stopped.request(2048), stopped);
    }
    for free in [511, 768] {
        let state = StateSnapshot(ARMED | KILLING | GENERATION_ONE | (2048 - free));
        assert_eq!(state.latch(2048, 1), None);
    }
}

fn pressure_receipts() {
    use crate::mm::AllocationFailure;
    use AllocationClass::*;
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    let pool = fixture.pool();
    pool.counters.state.store(ARMED, Ordering::Release);
    let floor = pool
        .allocation_result(pool.take_huge(HIGH, User), User)
        .unwrap_err();
    let state = pool.state_snapshot();
    assert_eq!(
        floor,
        AllocationFailure::Pressure {
            class: User,
            kind: RefusalKind::Floor,
            state,
            free_pages: 512,
        }
    );
    let gate = pool
        .allocation_result(pool.allocate(1, None, User), User)
        .unwrap_err();
    assert_eq!(
        gate,
        AllocationFailure::Pressure {
            class: User,
            kind: RefusalKind::Gate,
            state,
            free_pages: 512,
        }
    );
    assert_eq!(gate.retain_floor_refusal(Some(floor)), floor);
    // A search miss must still observe a closed gate, including fragmentation.
    assert_eq!(pool.allocation_result(Ok(None), User), Err(gate));
    let new_gate = AllocationFailure::Pressure {
        class: User,
        kind: RefusalKind::Gate,
        state: StateSnapshot(state.0 + 2 * GENERATION_ONE),
        free_pages: 512,
    };
    assert_eq!(new_gate.retain_floor_refusal(Some(floor)), floor);
    let capacity = pool.allocation_result(Ok(None), Kernel).unwrap_err();
    assert!(matches!(
        capacity,
        AllocationFailure::Pressure {
            kind: RefusalKind::Capacity,
            ..
        }
    ));
    for code in [
        moto_rt::E_OUT_OF_MEMORY,
        moto_rt::E_INVALID_ARGUMENT,
        moto_rt::E_BAD_HANDLE,
    ] {
        let ordinary = AllocationFailure::from(code);
        assert_eq!(ordinary, AllocationFailure::Code(code));
        assert_eq!(ordinary.retain_floor_refusal(Some(floor)), ordinary);
        assert_eq!(moto_sys::ErrorCode::from(ordinary), code);
    }
    assert_eq!(moto_sys::ErrorCode::from(floor), moto_rt::E_OUT_OF_MEMORY);
    assert_eq!(moto_sys::ErrorCode::from(gate), moto_rt::E_OUT_OF_MEMORY);
    check(&pool, 0);
}
