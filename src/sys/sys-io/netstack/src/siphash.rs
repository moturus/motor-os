//! SipHash-2-4, from Aumasson and Bernstein's "SipHash: a fast short-input
//! PRF" (2012).
//!
//! Used to derive TCP initial sequence numbers from the connection's 4-tuple
//! (RFC 6528), which needs a function a peer cannot invert or extrapolate from
//! the outputs it is allowed to see. [`crate::rand::Rand`] is the opposite: a
//! small linear generator whose whole state follows from a couple of outputs.
//!
//! Specified down to the byte, so the published test vectors below are what
//! makes this implementation checkable rather than merely plausible.

/// SipHash-2-4 under one 128-bit key.
///
/// No `Debug`: the key is a secret whose disclosure hands over every sequence
/// number derived from it, and a derived `Debug` is how secrets reach logs.
pub(crate) struct SipHasher24 {
    k0: u64,
    k1: u64,
}

impl SipHasher24 {
    /// `key` is the reference implementation's sixteen key bytes in its order,
    /// so the published vectors apply to this constructor unchanged.
    pub(crate) const fn new(key: [u8; 16]) -> Self {
        Self {
            k0: key_word(&key, 0),
            k1: key_word(&key, 8),
        }
    }

    /// The 64-bit tag of `msg`.
    pub(crate) fn hash(&self, msg: &[u8]) -> u64 {
        let mut state = State {
            v0: self.k0 ^ 0x736f_6d65_7073_6575,
            v1: self.k1 ^ 0x646f_7261_6e64_6f6d,
            v2: self.k0 ^ 0x6c79_6765_6e65_7261,
            v3: self.k1 ^ 0x7465_6462_7974_6573,
        };

        let mut blocks = msg.chunks_exact(8);
        for block in blocks.by_ref() {
            state.absorb(word(block));
        }

        // The last block is the leftover bytes with the message length in the
        // top one. That length byte is why messages that differ only in
        // trailing zeros -- or in how many bytes an address contributed --
        // cannot collide here.
        state.absorb(word(blocks.remainder()) | ((msg.len() as u64 & 0xff) << 56));
        state.finish()
    }
}

/// The four words SipRound mixes. The name's "2-4" is the two rounds every
/// message block gets and the four the tag gets.
struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);

        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;

        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;

        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    fn absorb(&mut self, word: u64) {
        self.v3 ^= word;
        self.round();
        self.round();
        self.v0 ^= word;
    }

    fn finish(mut self) -> u64 {
        self.v2 ^= 0xff;
        for _ in 0..4 {
            self.round();
        }
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// The little-endian word eight of `key`'s bytes stand for, from `at`.
const fn key_word(key: &[u8; 16], at: usize) -> u64 {
    u64::from_le_bytes([
        key[at],
        key[at + 1],
        key[at + 2],
        key[at + 3],
        key[at + 4],
        key[at + 5],
        key[at + 6],
        key[at + 7],
    ])
}

/// The little-endian word up to eight bytes stand for. Fewer than eight leaves
/// the high bytes zero, which is what the final block wants.
fn word(bytes: &[u8]) -> u64 {
    let mut word = 0;
    for (i, byte) in bytes.iter().enumerate() {
        word |= (*byte as u64) << (8 * i);
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SipHash-2-4 of the first `i` bytes of `00 01 .. 3e` under the key
    /// `00 01 .. 0f`, for every `i` in `0..64`. Appendix A of the paper, taken
    /// from the reference implementation's `vectors.h`.
    const VECTORS: [u64; 64] = [
        0x726f_db47_dd0e_0e31,
        0x74f8_39c5_93dc_67fd,
        0x0d6c_8009_d9a9_4f5a,
        0x8567_6696_d7fb_7e2d,
        0xcf27_94e0_2771_87b7,
        0x1876_5564_cd99_a68d,
        0xcbc9_466e_58fe_e3ce,
        0xab02_00f5_8b01_d137,
        0x93f5_f579_9a93_2462,
        0x9e00_82df_0ba9_e4b0,
        0x7a5d_bbc5_94dd_b9f3,
        0xf4b3_2f46_226b_ada7,
        0x751e_8fbc_860e_e5fb,
        0x14ea_5627_c084_3d90,
        0xf723_ca90_8e7a_f2ee,
        0xa129_ca61_49be_45e5,
        0x3f2a_cc7f_57c2_9bdb,
        0x699a_e9f5_2cbe_4794,
        0x4bc1_b3f0_968d_d39c,
        0xbb6d_c91d_a779_61bd,
        0xbed6_5cf2_1aa2_ee98,
        0xd0f2_cbb0_2e3b_67c7,
        0x9353_6795_e3a3_3e88,
        0xa80c_038c_cd5c_cec8,
        0xb8ad_50c6_f649_af94,
        0xbce1_92de_8a85_b8ea,
        0x17d8_35b8_5bbb_15f3,
        0x2f2e_6163_076b_cfad,
        0xde4d_aaac_a71d_c9a5,
        0xa6a2_5066_8795_6571,
        0xad87_a353_5c49_ef28,
        0x32d8_92fa_d841_c342,
        0x7127_512f_72f2_7cce,
        0xa7f3_2346_f959_78e3,
        0x12e0_b01a_bb05_1238,
        0x15e0_34d4_0fa1_97ae,
        0x314d_ffbe_0815_a3b4,
        0x0279_90f0_2962_3981,
        0xcadc_d4e5_9ef4_0c4d,
        0x9abf_d876_6a33_735c,
        0x0e3e_a96b_5304_a7d0,
        0xad0c_42d6_fc58_5992,
        0x1873_06c8_9bc2_15a9,
        0xd4a6_0abc_f379_2b95,
        0xf935_451d_e4f2_1df2,
        0xa953_8f04_1975_5787,
        0xdb9a_cddf_f56c_a510,
        0xd06c_98cd_5c09_75eb,
        0xe612_a3cb_9ecb_a951,
        0xc766_e62c_fcad_af96,
        0xee64_435a_9752_fe72,
        0xa192_d576_b245_165a,
        0x0a87_87bf_8ecb_74b2,
        0x81b3_e73d_20b4_9b6f,
        0x7fa8_220b_a3b2_ecea,
        0x2457_31c1_3ca4_2499,
        0xb78d_bfaf_3a8d_83bd,
        0xea1a_d565_322a_1a0b,
        0x60e6_1c23_a379_5013,
        0x6606_d7e4_4628_2b93,
        0x6ca4_ecb1_5c5f_91e1,
        0x9f62_6da1_5c96_25f3,
        0xe51b_3860_8ef2_5f57,
        0x958a_324c_eb06_4572,
    ];

    #[test]
    fn reference_vectors() {
        let hasher = SipHasher24::new(core::array::from_fn(|i| i as u8));
        let msg: [u8; 64] = core::array::from_fn(|i| i as u8);

        for (len, expected) in VECTORS.iter().enumerate() {
            assert_eq!(hasher.hash(&msg[..len]), *expected, "over {len} bytes");
        }
    }
}
