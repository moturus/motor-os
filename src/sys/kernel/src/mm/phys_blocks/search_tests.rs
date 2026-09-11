use super::*;

fn packing_and_bootstrap() {
    for runtime in [false, true] {
        let mut fixture = Fixture::new();
        for index in 0..4 {
            fixture.shape(index, 0, PAGES);
        }
        let pool = fixture.pool();
        let slot = AtomicUsize::new(NO_CURSOR);
        let cursor = runtime.then_some(&slot);
        assert_eq!(pool.allocate(0, cursor), Ok(None));
        assert_eq!(pool.allocate(513, cursor), Ok(None));
        for page in 0..2048 {
            assert_eq!(pool.allocate(1, cursor), Ok(Some(page * 4096)));
            check(&pool, page + 1);
        }
        assert_eq!(pool.allocate(1, cursor), Ok(None));
        assert_eq!(pool.allocate_huge(), Ok(None));
        if !runtime {
            for index in 0..4 {
                assert_eq!(
                    pool.block(index).unwrap().flags.load(Ordering::Relaxed) & CLAIMED,
                    0
                );
            }
        }
        // All split capacity is claimed in runtime mode; it must still be
        // reusable by a cursorless caller before exhaustion is reported.
        pool.push(4096).unwrap();
        assert_eq!(pool.allocate(1, None), Ok(Some(4096)));
        check(&pool, 2048);
    }
}

fn source_order_and_runs() {
    let mut fixture = Fixture::new();
    fixture.shape(0, 0, PAGES);
    fixture.shape(1, 10, 20);
    fixture.shape(HIGH, 0, PAGES);
    fixture.shape(HIGH + 1, 0, PAGES);
    let pool = fixture.pool();
    let cursor = AtomicUsize::new(NO_CURSOR);
    let other = AtomicUsize::new(NO_CURSOR);
    let partial = (1 << BLOCK_SHIFT) + 10 * 4096;
    assert_eq!(pool.allocate(1, Some(&cursor)), Ok(Some(partial)));
    // Claimed split capacity precedes even the lowest whole block.
    assert_eq!(pool.allocate(2, Some(&other)), Ok(Some(partial + 4096)));
    assert_eq!(pool.allocate(1, Some(&other)), Ok(Some(partial + 3 * 4096)));
    check(&pool, 4);
    // A short cursor tail survives a failed run. Lowest whole supplies it.
    assert_eq!(pool.allocate(65, Some(&cursor)), Ok(Some(0)));
    check(&pool, 69);
    assert_eq!(pool.allocate(6, Some(&other)), Ok(Some(partial + 4 * 4096)));
    check(&pool, 75);
    pool.push(partial).unwrap();
    pool.push(partial + 4096).unwrap();
    assert_eq!(pool.allocate(1, Some(&other)), Ok(Some(partial + 4096)));
    // The cursor stays sticky even though a lower block has capacity.
    assert_eq!(pool.allocate(1, Some(&other)), Ok(Some(partial)));
    assert_eq!(pool.allocate_huge(), Ok(Some(BASE + (1 << BLOCK_SHIFT))));
    assert_eq!(pool.allocate_huge(), Ok(Some(BASE)));
    check(&pool, 1099);
    assert_eq!(pool.allocate(448, Some(&cursor)), Ok(None));
    assert_eq!(pool.allocate(447, Some(&cursor)), Ok(Some(65 * 4096)));
    check(&pool, 1546);
    // A claimed list page must be found even when no whole capacity remains.
    pool.push(0).unwrap();
    assert_eq!(pool.allocate(1, Some(&other)), Ok(Some(0)));
    check(&pool, 1546);
}

fn shared_and_stale_cursors() {
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    fixture.shape(HIGH + 1, 10, 12);
    let pool = fixture.pool();
    let a = AtomicUsize::new(NO_CURSOR);
    let b = AtomicUsize::new(NO_CURSOR);
    let partial = BASE + (1 << BLOCK_SHIFT) + 10 * 4096;
    assert_eq!(pool.allocate(1, Some(&a)), Ok(Some(partial)));
    assert_eq!(pool.allocate(1, Some(&b)), Ok(Some(partial + 4096)));
    assert_eq!(pool.allocate(1, Some(&a)), Ok(Some(BASE)));
    pool.push(partial).unwrap();
    // An unclaimed split beats the lower claimed split when adopting a cursor.
    let c = AtomicUsize::new(NO_CURSOR);
    assert_eq!(pool.allocate(1, Some(&c)), Ok(Some(partial)));
    assert_eq!(pool.allocate(1, Some(&b)), Ok(Some(BASE + 4096)));
    assert_eq!(a.load(Ordering::Relaxed), b.load(Ordering::Relaxed));
    pool.push(BASE).unwrap();
    pool.push(BASE + 4096).unwrap();
    check(&pool, 2);
    assert_eq!(pool.allocate_huge(), Ok(Some(BASE)));
    assert_eq!(pool.allocate(1, Some(&a)), Ok(None));
    pool.return_huge(BASE).unwrap();
    assert_eq!(pool.allocate(1, Some(&b)), Ok(Some(BASE)));
    // A stale cursor can adopt the same block after take/return/re-split.
    a.store(HIGH, Ordering::Relaxed);
    assert_eq!(pool.allocate(1, Some(&a)), Ok(Some(BASE + 4096)));
    assert_eq!(pool.allocate(511, Some(&a)), Ok(None));
    assert_eq!(
        pool.block(HIGH).unwrap().flags.load(Ordering::Relaxed) & CLAIMED,
        0
    );
    // Clearing a shared hint did not invalidate the other cursor's ownership.
    assert_eq!(pool.allocate(1, Some(&b)), Ok(Some(BASE + 2 * 4096)));
    check(&pool, 5);
}

pub(super) fn run() {
    packing_and_bootstrap();
    source_order_and_runs();
    shared_and_stale_cursors();
    crate::raw_log!("phys_blocks search tests PASS");
}
