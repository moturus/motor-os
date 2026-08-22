mod cubic;

pub(super) use cubic::Cubic;

/// RFC 6928 section 2's initial congestion window: `min(10*MSS, max(2*MSS,
/// 14600))`. RFC 5681 section 3.1's smaller one is the same expression with 4
/// and 4380.
///
/// The controller constructs with a placeholder window because it is built before
/// the handshake, when no MSS is known; this is what the placeholder becomes once
/// one is. Sizing it in segments is the whole point -- the window exists to bound
/// how much is in flight, and a segment is the unit that travels.
pub(super) fn initial_window(mss: usize) -> usize {
    const SEGMENTS: usize = 10;
    const CAP: usize = 14600;

    (SEGMENTS * mss).min(CAP.max(2 * mss))
}
