use super::*;
use crate::mm::phys_blocks::{ABSENT, PAGES, SPLIT, WHOLE};
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
        [pages(0, 640 * K), pages(M, 34 * M), pages(38 * M, 64 * M)]
    );
    assert_eq!(layout.reserved, from_ref(&pages(0, 34 * M)));
    assert_eq!(layout.initrd, pages(38 * M, 39 * M + 4 * K));
    assert_eq!(layout.ram, from_ref(&(0..32)));
    assert_eq!(layout.blocks, 32);

    // Inward page rounding, adjacency coalescing, outward reservation
    // rounding, and empty or trimmed-empty segments.
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
    assert_eq!(layout.managed, [2..8, 9..8704, pages(38 * M, 64 * M)]);
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
    assert_eq!(layout.managed[2], pages(100 * M + 4 * K, 102 * M));
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
    span();
    storage();
    crate::raw_log!("phys_blocks layout tests PASS");
}

fn expect(
    shaped: &Shaped,
    state: u8,
    flags: u8,
    alloc: Range<u16>,
    unused: Range<u16>,
    counts: (u16, u16, u16, u16),
) {
    let shape = &shaped.shape;
    assert_eq!((shape.state, shaped.flags), (state, flags));
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

fn span() {
    // 300 RAM blocks plus a distant one: the low reservation, the kernel gap,
    // a three-block initrd, and one reserved page per block above it, so
    // more than 255 blocks are mixed. Blocks 30 and 299 stay whole.
    let raw = [seg(0, 600 * M), seg(700 * M, 702 * M)];
    let available = [seg(0, 34 * M), seg(38 * M, 600 * M)];
    let mut reserved = alloc::vec![seg(0, 34 * M)];
    for block in (22..299u64).filter(|block| *block != 30) {
        let start = block * 2 * M + block * 4 * K;
        reserved.push(seg(start, start + 4 * K));
    }
    let initrd = seg(39 * M + 4 * K, 43 * M + 8 * K);
    let mut layout = Layout::new(&available, &reserved, initrd, &raw).unwrap();
    assert_eq!(layout.blocks, 351);

    let mut managed = 0;
    let mut reserved = 0;
    let mut discarded = 0;
    let mut states = [0; 3];
    let mut mixed = 0;
    for index in 0..layout.blocks {
        let shaped = layout.block(index).unwrap();
        let shape = &shaped.shape;
        assert_eq!(shaped.flags & RAM != 0, index < 300 || index == 350);
        assert_eq!(shaped.flags & SMALL_ONLY != 0, index < 64);
        managed += u64::from(shape.managed);
        reserved += u64::from(shape.reserved);
        discarded += u64::from(shape.discarded);
        states[usize::from(shape.state)] += 1;
        if shape.state == SPLIT && (shape.inner.alloc_lo != 0 || shape.inner.alloc_hi != PAGES) {
            mixed += 1;
        }
    }
    // Independent expectations: the smaller run beside each reserved page is
    // discarded, and low RAM is entirely reserved.
    let low_reserved = 17 * 512;
    let (mut per_block_reserved, mut per_block_discarded) = (0, 0);
    for block in (22..299u64).filter(|block| *block != 30) {
        let smaller = block.min(511 - block);
        per_block_reserved += 1 + smaller;
        per_block_discarded += smaller;
    }
    assert_eq!(managed, 298 * 512);
    assert_eq!(reserved, low_reserved + per_block_reserved);
    assert_eq!(discarded, per_block_discarded);
    assert_eq!(states, [53, 2, 296]);
    // 276 blocks with a reserved page, plus the 17 fully reserved low blocks.
    assert_eq!(mixed, 293);

    let low = RAM | SMALL_ONLY;
    expect(
        &layout.block(0).unwrap(),
        SPLIT,
        low,
        0..0,
        0..0,
        (512, 512, 0, 512),
    );
    expect(
        &layout.block(3).unwrap(),
        SPLIT,
        low,
        0..0,
        0..0,
        (512, 512, 0, 512),
    );
    expect(
        &layout.block(17).unwrap(),
        ABSENT,
        low,
        0..0,
        0..0,
        (0, 0, 0, 512),
    );
    expect(
        &layout.block(19).unwrap(),
        SPLIT,
        low,
        0..512,
        0..257,
        (512, 0, 0, 255),
    );
    expect(
        &layout.block(20).unwrap(),
        SPLIT,
        low,
        0..512,
        0..0,
        (512, 0, 0, 512),
    );
    expect(
        &layout.block(21).unwrap(),
        SPLIT,
        low,
        0..512,
        258..512,
        (512, 0, 0, 258),
    );
    expect(
        &layout.block(22).unwrap(),
        SPLIT,
        low,
        23..512,
        23..512,
        (512, 23, 22, 23),
    );
    expect(
        &layout.block(30).unwrap(),
        WHOLE,
        low,
        0..512,
        0..0,
        (512, 0, 0, 0),
    );
    expect(
        &layout.block(64).unwrap(),
        SPLIT,
        RAM,
        65..512,
        65..512,
        (512, 65, 64, 65),
    );
    expect(
        &layout.block(256).unwrap(),
        SPLIT,
        RAM,
        0..256,
        0..256,
        (512, 256, 255, 256),
    );
    expect(
        &layout.block(299).unwrap(),
        WHOLE,
        RAM,
        0..512,
        0..0,
        (512, 0, 0, 0),
    );
    expect(
        &layout.block(320).unwrap(),
        ABSENT,
        0,
        0..0,
        0..0,
        (0, 0, 0, 512),
    );
    expect(
        &layout.block(350).unwrap(),
        ABSENT,
        RAM,
        0..0,
        0..0,
        (0, 0, 0, 512),
    );
}

fn storage() {
    // Table rounding: 64 bytes per block, 64 blocks per page.
    for (blocks, lines, words) in [
        (1, 1, 1),
        (63, 16, 1),
        (64, 16, 1),
        (65, 17, 2),
        (MAX_BLOCKS, 8192, 512),
    ] {
        assert_eq!(
            Budget::preflight(blocks).unwrap(),
            Budget {
                lines,
                words,
                table_pages: words as u16,
            }
        );
    }
    assert_eq!(Budget::preflight(MAX_BLOCKS + 1), Err(LayoutError::Span));

    // The table backs onto the lowest run that fits: a whole block, a partial
    // retained run beside the initrd, or nothing at all.
    let raw = [seg(0, 64 * M)];
    let available = [seg(0, 34 * M), seg(38 * M, 64 * M)];
    let mut layout = standard(&available, NONE, &raw).unwrap();
    assert_eq!(layout.carve_table(0), Ok(None));
    assert_eq!(layout.carve_table(1), Ok(Some((19, 0))));
    assert_eq!(layout.carve_table(512), Ok(Some((19, 0))));
    let mut shape = layout.block(19).unwrap().shape;
    assert_eq!(shape.carve(513), Err(ShapeError::Bounds));
    shape.carve(3).unwrap();
    assert_eq!(shape.state, SPLIT);
    assert_eq!(shape.inner.alloc_lo..shape.inner.alloc_hi, 0..512);
    assert_eq!(shape.inner.unused_lo..shape.inner.unused_hi, 3..512);
    assert_eq!(shape.inner.used, 3);
    shape.inner.check_bounds().unwrap();

    let mut layout = standard(&available, seg(38 * M, 39 * M), &raw).unwrap();
    assert_eq!(layout.carve_table(256), Ok(Some((19, 256))));
    assert_eq!(layout.carve_table(257), Ok(Some((20, 0))));
    let mut shape = layout.block(19).unwrap().shape;
    assert_eq!(shape.carve(257), Err(ShapeError::Bounds));
    shape.carve(256).unwrap();
    assert_eq!(shape.state, SPLIT);
    assert_eq!(shape.inner.alloc_lo..shape.inner.alloc_hi, 0..512);
    assert_eq!(shape.inner.unused_lo..shape.inner.unused_hi, 512..512);
    assert_eq!(shape.inner.used, 512);
    assert_eq!(shape.carve(1), Err(ShapeError::Bounds));

    let reserved = [seg(0, 34 * M), seg(38 * M + 8 * K, 64 * M)];
    let mut layout = Layout::new(&available, &reserved, NONE, &raw).unwrap();
    assert_eq!(layout.carve_table(2), Ok(Some((19, 0))));
    assert_eq!(layout.carve_table(3), Ok(None));
    let mut shape = layout.block(0).unwrap().shape;
    assert_eq!(shape.carve(1), Err(ShapeError::Bounds));
    let mut shape = layout.block(17).unwrap().shape;
    assert_eq!(shape.carve(1), Err(ShapeError::Bounds));
}
