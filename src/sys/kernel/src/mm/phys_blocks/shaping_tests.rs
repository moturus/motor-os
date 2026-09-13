use super::*;
use core::slice::from_ref;

fn expect(
    shape: Shape,
    state: u8,
    alloc: Range<u16>,
    unused: Range<u16>,
    counts: (u16, u16, u16, u16),
) {
    shape.inner.check_bounds().unwrap();
    assert_eq!(shape.state, state);
    assert_eq!(shape.inner.head, 0);
    assert_eq!(shape.inner.alloc_lo..shape.inner.alloc_hi, alloc);
    assert_eq!(shape.inner.unused_lo..shape.inner.unused_hi, unused);
    assert_eq!(
        (
            shape.managed,
            shape.reserved,
            shape.discarded,
            shape.inner.used
        ),
        counts
    );
}

pub(super) fn run() {
    expect(
        Shape::new(&[], &[], 0..0).unwrap(),
        ABSENT,
        0..0,
        0..0,
        (0, 0, 0, 512),
    );
    expect(
        Shape::new(from_ref(&(0..512)), &[], 0..0).unwrap(),
        WHOLE,
        0..512,
        0..0,
        (512, 0, 0, 0),
    );
    // A disconnected larger run is discarded when only the smaller run
    // touches the initrd. No allocatable interval crosses the firmware hole.
    expect(
        Shape::new(&[0..300, 400..512], &[], 400..450).unwrap(),
        SPLIT,
        400..512,
        450..512,
        (412, 300, 300, 450),
    );
    expect(
        Shape::new(from_ref(&(0..512)), &[], 200..312).unwrap(),
        SPLIT,
        0..312,
        0..200,
        (512, 200, 200, 312),
    );
    expect(
        Shape::new(&[0..100, 200..300], &[], 0..0).unwrap(),
        SPLIT,
        0..100,
        0..100,
        (200, 100, 100, 412),
    );
    expect(
        Shape::new(from_ref(&(0..512)), &[100..200, 300..400], 0..0).unwrap(),
        SPLIT,
        400..512,
        400..512,
        (512, 400, 200, 400),
    );
    expect(
        Shape::new(from_ref(&(100..200)), &[], 100..200).unwrap(),
        SPLIT,
        100..200,
        0..0,
        (100, 0, 0, 512),
    );
    expect(
        Shape::new(from_ref(&(0..512)), &[], 0..512).unwrap(),
        SPLIT,
        0..512,
        0..0,
        (512, 0, 0, 512),
    );
    // Coalesce adjacent managed ranges before selecting the longest run.
    expect(
        Shape::new(&[0..100, 100..512], &[], 0..0).unwrap(),
        WHOLE,
        0..512,
        0..0,
        (512, 0, 0, 0),
    );
    expect(
        Shape::new(&[0..100, 100..512], &[], 90..110).unwrap(),
        SPLIT,
        90..512,
        110..512,
        (512, 90, 90, 110),
    );
    // Before stage 2 all managed low RAM is reserved; afterwards page zero
    // and two loader-table pages remain reserved. Firmware holes stay absent.
    expect(
        Shape::new(&[0..128, 256..512], from_ref(&(0..512)), 0..0).unwrap(),
        SPLIT,
        0..0,
        0..0,
        (384, 384, 0, 512),
    );
    expect(
        Shape::new(&[0..128, 256..512], &[0..1, 300..301, 400..401], 0..0).unwrap(),
        SPLIT,
        1..128,
        1..128,
        (384, 257, 254, 385),
    );
    expect(
        Shape::new(from_ref(&(10..20)), &[0..5, 15..30], 0..0).unwrap(),
        SPLIT,
        10..15,
        10..15,
        (10, 5, 0, 507),
    );

    for managed in [
        from_ref(&(0..513)),
        from_ref(&(10..10)),
        &[0..20, 19..30],
        &[20..30, 0..10],
    ] {
        assert!(Shape::new(managed, &[], 0..0).is_err());
    }
    assert!(matches!(
        Shape::new(from_ref(&(0..512)), from_ref(&(3..513)), 0..0),
        Err(ShapeError::Bounds)
    ));
    assert!(matches!(
        Shape::new(from_ref(&(0..512)), &[0..2, 1..3], 0..0),
        Err(ShapeError::Overlap)
    ));
    for (start, end) in [(1, 1), (20, 10), (0, 513)] {
        assert!(matches!(
            Shape::new(from_ref(&(0..512)), &[], start..end),
            Err(ShapeError::Bounds)
        ));
    }
    for initrd in [50..150, 90..210, 300..400] {
        assert!(matches!(
            Shape::new(&[0..100, 200..300], &[], initrd),
            Err(ShapeError::Initrd)
        ));
    }
    assert!(matches!(
        Shape::new(from_ref(&(0..512)), from_ref(&(100..101)), 90..110),
        Err(ShapeError::Initrd)
    ));
    crate::raw_log!("phys_blocks shaping tests PASS");
}
