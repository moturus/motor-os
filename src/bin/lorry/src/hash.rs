use crate::diagnostic::{Error, Result};
use std::fs::File;
use std::hash::Hasher;
use std::io::Read;
use std::path::Path;

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    bytes: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            bytes: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.bytes = self
            .bytes
            .checked_add(input.len() as u64)
            .expect("SHA-256 input length overflow");
        if self.buffered != 0 {
            let needed = 64 - self.buffered;
            let taken = needed.min(input.len());
            self.buffer[self.buffered..self.buffered + taken].copy_from_slice(&input[..taken]);
            self.buffered += taken;
            input = &input[taken..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            } else {
                return;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().unwrap();
            self.compress(block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bit_length = self
            .bytes
            .checked_mul(8)
            .expect("SHA-256 bit length overflow");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut output = [0; 32];
        for (chunk, value) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        output
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for (word, constant) in schedule.into_iter().zip(K) {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(sigma1)
                .wrapping_add(choice)
                .wrapping_add(constant)
                .wrapping_add(word);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| {
        Error::failure(format!(
            "failed to open `{}` for hashing: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Error::failure(format!("failed to hash `{}`: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finish())
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

/// Cargo 1.97/1.98's cross-platform `rustc-stable-hash` byte contract.
///
/// Storing the small metadata stream before SipHash finalization keeps this
/// implementation dependency-free and easy to compare against fixed Cargo
/// oracle vectors.
#[derive(Clone, Default)]
pub struct StableHasher {
    bytes: Vec<u8>,
}

impl StableHasher {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Hasher for StableHasher {
    fn finish(&self) -> u64 {
        let [low, high] = siphash_128(&self.bytes);
        low.wrapping_mul(3).wrapping_add(high)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write_u64(value as u64);
        self.write_u64((value >> 64) as u64);
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }

    fn write_i8(&mut self, value: i8) {
        self.write_u8(value as u8);
    }

    fn write_i16(&mut self, value: i16) {
        self.write_u16(value as u16);
    }

    fn write_i32(&mut self, value: i32) {
        self.write_u32(value as u32);
    }

    fn write_i64(&mut self, value: i64) {
        self.write_u64(value as u64);
    }

    fn write_i128(&mut self, value: i128) {
        self.write(&(value as u128).to_le_bytes());
    }

    fn write_isize(&mut self, value: isize) {
        let value = value as u64;
        if value < 0xff {
            self.write_u8(value as u8);
        } else {
            self.write_u8(0xff);
            self.write_u64(value);
        }
    }
}

fn siphash_128(input: &[u8]) -> [u64; 2] {
    let mut state = SipState {
        v0: 0x736f6d6570736575,
        v1: 0x646f72616e646f6d ^ 0xee,
        v2: 0x6c7967656e657261,
        v3: 0x7465646279746573,
    };
    let mut chunks = input.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        state.v3 ^= word;
        state.round();
        state.v0 ^= word;
    }
    let remainder = chunks.remainder();
    let mut final_word = (input.len() as u64 & 0xff) << 56;
    for (shift, byte) in remainder.iter().enumerate() {
        final_word |= (*byte as u64) << (shift * 8);
    }
    state.v3 ^= final_word;
    state.round();
    state.v0 ^= final_word;

    state.v2 ^= 0xee;
    state.rounds(3);
    let low = state.v0 ^ state.v1 ^ state.v2 ^ state.v3;
    state.v1 ^= 0xdd;
    state.rounds(3);
    let high = state.v0 ^ state.v1 ^ state.v2 ^ state.v3;
    [low, high]
}

struct SipState {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl SipState {
    fn rounds(&mut self, count: usize) {
        for _ in 0..count {
            self.round();
        }
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    #[test]
    fn matches_sha256_known_answers_and_chunk_boundaries() {
        for (input, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut hasher = Sha256::new();
            for chunk in input.chunks(2) {
                hasher.update(chunk);
            }
            assert_eq!(hex(&hasher.finish()), expected);
        }
    }

    #[test]
    fn matches_cargo_stable_hash_golden_vectors() {
        let mut empty = StableHasher::new();
        ().hash(&mut empty);
        assert_eq!(empty.finish(), 0x1cba18e857884f2a);

        let mut structured = StableHasher::new();
        (
            2u8,
            "red",
            "0.1.0",
            vec!["feature-a", "feature-b"],
            Some(42u32),
        )
            .hash(&mut structured);
        assert_eq!(structured.finish(), 0x54782f4bcf038193);
    }
}
