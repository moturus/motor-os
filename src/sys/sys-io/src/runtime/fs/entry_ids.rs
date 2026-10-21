//! Per-boot wire IDs. Internal filesystem users keep canonical, unencoded IDs.

use core::arch::x86_64::*;

pub(super) struct EntryIds {
    keys: Option<AesKeys>,
    // AES_K(0) in AES mode; the nonzero random seed in XOR mode.
    mask: u128,
}

fn aes_available() -> bool {
    // CPUID is available on every x86-64 CPU.
    unsafe { __cpuid(1).ecx & (1 << 25) != 0 }
}

impl EntryIds {
    pub(super) fn new() -> Self {
        let mut seed = [0; 16];
        moto_rt::fill_random_bytes(&mut seed);
        if aes_available() {
            // This is the only production constructor of AES keys. All later
            // AES calls rely on this check; no AES instructions run otherwise.
            let keys = unsafe { AesKeys::new(seed) };
            let mask = unsafe { keys.encrypt(0) };
            Self {
                keys: Some(keys),
                mask,
            }
        } else {
            while seed == [0; 16] {
                moto_rt::fill_random_bytes(&mut seed);
            }
            log::warn!(
                "AES-NI unavailable: entry IDs use weak XOR obfuscation; hidden IDs can be guessed"
            );
            Self {
                keys: None,
                mask: u128::from_le_bytes(seed),
            }
        }
    }

    pub(super) fn encode(&self, id: u128) -> u128 {
        match &self.keys {
            // `keys` exists only after checking CPUID.
            Some(keys) => unsafe { keys.encrypt(id) ^ self.mask },
            None => self.xor(id),
        }
    }

    pub(super) fn decode(&self, id: u128) -> u128 {
        match &self.keys {
            // `keys` exists only after checking CPUID.
            Some(keys) => unsafe { keys.decrypt(id ^ self.mask) },
            None => self.xor(id),
        }
    }

    fn xor(&self, id: u128) -> u128 {
        // Plain XOR swaps 0 and the seed. Fix both to preserve the root ID
        // without making any other ID map to zero.
        if id == 0 || id == self.mask {
            id
        } else {
            id ^ self.mask
        }
    }
}

struct AesKeys {
    enc: [__m128i; 11],
    dec: [__m128i; 11],
}

#[target_feature(enable = "aes")]
fn next_key<const RCON: i32>(mut key: __m128i) -> __m128i {
    let assist = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<RCON>(key));
    let mut shifted = key;
    for _ in 0..3 {
        shifted = _mm_slli_si128::<4>(shifted);
        key = _mm_xor_si128(key, shifted);
    }
    _mm_xor_si128(key, assist)
}

impl AesKeys {
    #[target_feature(enable = "aes")]
    unsafe fn new(key: [u8; 16]) -> Self {
        // Both types are exactly 16 bytes and accept every bit pattern.
        let mut enc = [unsafe { core::mem::transmute::<[u8; 16], __m128i>(key) }; 11];
        enc[1] = next_key::<0x01>(enc[0]);
        enc[2] = next_key::<0x02>(enc[1]);
        enc[3] = next_key::<0x04>(enc[2]);
        enc[4] = next_key::<0x08>(enc[3]);
        enc[5] = next_key::<0x10>(enc[4]);
        enc[6] = next_key::<0x20>(enc[5]);
        enc[7] = next_key::<0x40>(enc[6]);
        enc[8] = next_key::<0x80>(enc[7]);
        enc[9] = next_key::<0x1b>(enc[8]);
        enc[10] = next_key::<0x36>(enc[9]);
        let mut dec = enc;
        dec.reverse();
        for key in &mut dec[1..10] {
            *key = _mm_aesimc_si128(*key);
        }
        Self { enc, dec }
    }

    #[target_feature(enable = "aes")]
    unsafe fn encrypt(&self, id: u128) -> u128 {
        // AES blocks use the ID's little-endian bytes, including at the output.
        let block = unsafe { core::mem::transmute::<[u8; 16], __m128i>(id.to_le_bytes()) };
        let mut block = _mm_xor_si128(block, self.enc[0]);
        for key in &self.enc[1..10] {
            block = _mm_aesenc_si128(block, *key);
        }
        let block = _mm_aesenclast_si128(block, self.enc[10]);
        u128::from_le_bytes(unsafe { core::mem::transmute::<__m128i, [u8; 16]>(block) })
    }

    #[target_feature(enable = "aes")]
    unsafe fn decrypt(&self, id: u128) -> u128 {
        let block = unsafe { core::mem::transmute::<[u8; 16], __m128i>(id.to_le_bytes()) };
        let mut block = _mm_xor_si128(block, self.dec[0]);
        for key in &self.dec[1..10] {
            block = _mm_aesdec_si128(block, *key);
        }
        let block = _mm_aesdeclast_si128(block, self.dec[10]);
        u128::from_le_bytes(unsafe { core::mem::transmute::<__m128i, [u8; 16]>(block) })
    }
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::entry_ids", codecs)];

    fn round_trips(codec: &EntryIds) -> Result<(), String> {
        let ids = [
            0,
            1,
            1 << 63,
            1 << 64,
            1 << 127,
            u128::MAX,
            codec.mask,
            !codec.mask,
        ];
        st_assert_eq!(codec.encode(0), 0);
        st_assert_eq!(codec.decode(0), 0);
        for id in ids.into_iter().chain(1..4096) {
            let wire = codec.encode(id);
            st_assert_eq!(wire == 0, id == 0);
            st_assert_eq!(codec.decode(wire), id);
            st_assert_eq!(codec.encode(codec.decode(id)), id);
        }
        Ok(())
    }

    fn codecs() -> Result<(), String> {
        for mask in [1, 1 << 127, u128::MAX, 0x123456789abcdef] {
            let xor = EntryIds { keys: None, mask };
            st_assert_eq!(xor.encode(mask), mask);
            st_assert_eq!(xor.decode(mask), mask);
            st_assert_eq!(
                xor.encode(!mask),
                if mask == u128::MAX { 0 } else { u128::MAX }
            );
            round_trips(&xor)?;
        }
        if aes_available() {
            // NIST AES_Core128.pdf, first ECB block. The literals spell bytes
            // in publication order; IDs interpret those bytes as little-endian.
            let key = 0x2b7e151628aed2a6abf7158809cf4f3cu128.to_be_bytes();
            let plain = u128::from_le_bytes(0x6bc1bee22e409f96e93d7e117393172au128.to_be_bytes());
            let cipher = u128::from_le_bytes(0x3ad77bb40d7a3660a89ecaf32466ef97u128.to_be_bytes());
            let keys = unsafe { AesKeys::new(key) };
            st_assert_eq!(unsafe { keys.encrypt(plain) }, cipher);
            st_assert_eq!(unsafe { keys.decrypt(cipher) }, plain);
            let mask = unsafe { keys.encrypt(0) };
            let aes = EntryIds {
                keys: Some(keys),
                mask,
            };
            st_assert_eq!(aes.encode(plain), cipher ^ mask);
            st_assert!(aes.encode(plain) != plain);
            round_trips(&aes)?;
        }
        Ok(())
    }
}
