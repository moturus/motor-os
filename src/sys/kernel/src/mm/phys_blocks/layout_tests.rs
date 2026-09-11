use super::*;
use core::slice::from_ref;

const K: u64 = 1 << 10;
const M: u64 = 1 << 20;
const G: u64 = 1 << 30;

fn seg(start: u64, end: u64) -> MemorySegment {
    MemorySegment {
        start,
        size: end - start,
    }
}

fn pages(start: u64, end: u64) -> Range<u64> {
    (start >> PAGE_SHIFT)..(end >> PAGE_SHIFT)
}

const NONE: MemorySegment = MemorySegment { start: 0, size: 0 };
const LOW: [MemorySegment; 1] = [MemorySegment {
    start: 0,
    size: 34 * M,
}];

fn standard(
    available: &[MemorySegment],
    initrd: MemorySegment,
    raw: &[MemorySegment],
) -> Result<Layout, LayoutError> {
    Layout::new(available, &LOW, initrd, raw)
}

pub(super) fn run() {
    // A typical boot: the kernel and boot heap [34M, 38M) are already removed
    // and the initrd sits above them, unaligned at both ends.
    let raw = [seg(0, 640 * K), seg(M, 64 * M)];
    let available = [seg(0, 640 * K), seg(M, 34 * M), seg(38 * M, 64 * M)];
    let layout = standard(&available, seg(38 * M + 100, 39 * M + 100), &raw).unwrap();
    assert_eq!(
        layout.managed,
        [
            pages(0, 640 * K),
            pages(M, 2 * M),
            pages(10 * M, 34 * M),
            pages(38 * M, 64 * M)
        ]
    );
    assert_eq!(layout.reserved, from_ref(&pages(0, 34 * M)));
    assert_eq!(layout.initrd, pages(38 * M, 39 * M + 4 * K));
    assert_eq!(layout.ram, from_ref(&(0..32)));
    assert_eq!(layout.blocks, 32);

    // Inward page rounding, adjacency coalescing before the fixed-mid check,
    // outward reservation rounding, and empty or trimmed-empty segments.
    let raw = [seg(0, 64 * M), seg(64 * M, 65 * M)];
    let available = [
        seg(0x1003, 0x5000),
        seg(0x5000, 0x8fff),
        seg(0x9000, 5 * M),
        seg(5 * M, 5 * M),
        seg(5 * M, 34 * M),
        seg(38 * M, 64 * M),
        seg(64 * M + 1, 64 * M + 0xfff),
    ];
    let reserved = [seg(0x800, 0x1800), seg(0x1800, 34 * M)];
    let layout = Layout::new(&available, &reserved, NONE, &raw).unwrap();
    assert_eq!(
        layout.managed,
        [2..8, 9..512, 2560..8704, pages(38 * M, 64 * M)]
    );
    assert_eq!(layout.reserved, from_ref(&(0..8704)));
    assert_eq!(layout.initrd, 0..0);
    assert_eq!(layout.ram, from_ref(&(0..33)));
    assert_eq!(layout.blocks, 33);

    // Raw RAM marks blocks even where nothing is managed, and holes stay
    // inside the span. The 64 GiB span limit is inclusive.
    let raw = [
        seg(0, 64 * M),
        seg(100 * M + 4 * K, 102 * M),
        seg(200 * M, 201 * M),
    ];
    let available = [
        seg(0, 34 * M),
        seg(38 * M, 64 * M),
        seg(100 * M + 4 * K, 102 * M),
    ];
    let layout = standard(&available, NONE, &raw).unwrap();
    assert_eq!(layout.managed[3], pages(100 * M + 4 * K, 102 * M));
    assert_eq!(layout.ram, [0..32, 50..51, 100..101]);
    assert_eq!(layout.blocks, 101);
    let raw = [seg(0, 64 * G)];
    let available = [seg(0, 34 * M), seg(38 * M, 64 * G)];
    let layout = standard(&available, seg(38 * M, 40 * M), &raw).unwrap();
    assert_eq!(layout.blocks, MAX_BLOCKS);
    assert_eq!(layout.initrd, pages(38 * M, 40 * M));
    let raw = [seg(0, 64 * G + 4 * K)];
    assert_eq!(
        standard(&available, NONE, &raw).err(),
        Some(LayoutError::Span)
    );

    let raw = [seg(0, 64 * M)];
    let available = [seg(0, 34 * M), seg(38 * M, 64 * M)];
    assert!(standard(&available, NONE, &raw).is_ok());
    let wrapped = MemorySegment {
        start: u64::MAX - 100,
        size: 200,
    };
    assert_eq!(
        standard(&available, NONE, &[seg(0, 64 * M), wrapped]).err(),
        Some(LayoutError::Arithmetic)
    );
    assert_eq!(
        standard(&[seg(38 * M, 64 * M), seg(0, 34 * M)], NONE, &raw).err(),
        Some(LayoutError::Order)
    );
    assert_eq!(
        standard(&available, NONE, &[seg(0, 40 * M), seg(39 * M, 64 * M)]).err(),
        Some(LayoutError::Order)
    );
    assert_eq!(
        Layout::new(&available, &[seg(M, 2 * M), seg(0, 34 * M)], NONE, &raw).err(),
        Some(LayoutError::Order)
    );
    for available in [
        [seg(0, 2 * M), seg(10 * M, 34 * M), seg(38 * M, 64 * M)],
        [
            seg(0, 6 * M),
            seg(6 * M + 4 * K, 34 * M),
            seg(38 * M, 64 * M),
        ],
    ] {
        assert_eq!(
            standard(&available, NONE, &raw).err(),
            Some(LayoutError::FixedMid)
        );
    }
    assert_eq!(
        standard(&[seg(0, 34 * M), seg(38 * M, 64 * M + 4 * K)], NONE, &raw).err(),
        Some(LayoutError::Raw)
    );
    assert_eq!(
        standard(
            &[seg(0, 34 * M), seg(38 * M, 64 * M), seg(70 * M, 72 * M)],
            NONE,
            &raw
        )
        .err(),
        Some(LayoutError::Raw)
    );

    // An initrd must be page-contained in one managed run: not across a
    // firmware hole, not past the end of RAM, not over a reservation.
    let raw = [seg(0, 64 * M), seg(66 * M, 80 * M)];
    let available = [seg(0, 34 * M), seg(38 * M, 64 * M), seg(66 * M, 80 * M)];
    assert!(standard(&available, seg(63 * M, 64 * M), &raw).is_ok());
    assert!(standard(&available, seg(66 * M, 67 * M), &raw).is_ok());
    for initrd in [
        seg(63 * M, 67 * M),
        seg(63 * M, 64 * M + 1),
        seg(79 * M, 80 * M + 1),
        seg(30 * M, 31 * M),
        seg(33 * M + 4 * K - 1, 39 * M),
    ] {
        assert_eq!(
            standard(&available, initrd, &raw).err(),
            Some(LayoutError::Initrd)
        );
    }
    let reserved = [seg(0, 34 * M), seg(40 * M, 41 * M)];
    assert_eq!(
        Layout::new(&available, &reserved, seg(39 * M, 42 * M), &raw).err(),
        Some(LayoutError::Initrd)
    );
    assert!(Layout::new(&available, &reserved, seg(41 * M, 42 * M), &raw).is_ok());
    crate::raw_log!("phys_blocks layout tests PASS");
}
