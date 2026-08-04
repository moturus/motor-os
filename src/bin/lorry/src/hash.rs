use crate::diagnostic::{Error, Result};
use sha2::{Digest, Sha256 as Sha256Backend};
use std::fs::File;
use std::hash::Hasher;
use std::io::Read;
use std::path::Path;

#[derive(Clone)]
pub struct Sha256(Sha256Backend);

impl Sha256 {
    pub fn new() -> Self {
        Self(Sha256Backend::new())
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
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

#[allow(dead_code)]
pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::failure(format!(
            "expected {} lowercase hexadecimal digits",
            N * 2
        )));
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("decode_hex validated every digit"),
    }
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

        let large: Vec<_> = (0..1_000_003).map(|index| index as u8).collect();
        let mut expected = Sha256::new();
        expected.update(&large);
        let expected = expected.finish();
        for chunk_size in [1, 3, 63, 64, 65, 4096, 65_537] {
            let mut partitioned = Sha256::new();
            for chunk in large.chunks(chunk_size) {
                partitioned.update(chunk);
            }
            assert_eq!(partitioned.finish(), expected, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn strict_hex_round_trips_and_rejects_noncanonical_input() {
        let bytes = decode_hex::<4>("0010abff").unwrap();
        assert_eq!(bytes, [0x00, 0x10, 0xab, 0xff]);
        assert_eq!(hex(&bytes), "0010abff");
        for invalid in ["0010ab", "0010ABff", "0010agff"] {
            assert!(decode_hex::<4>(invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn matches_host_sha256sum_oracle() {
        use std::fs;
        use std::process::Command;

        let path = std::env::temp_dir().join(format!("lorry-sha256-oracle-{}", std::process::id()));
        let contents: Vec<_> = (0..262_147).map(|index| (index * 17) as u8).collect();
        fs::write(&path, contents).unwrap();
        let actual = sha256_file(&path).unwrap();
        let output = Command::new("sha256sum").arg(&path).output().unwrap();
        let _ = fs::remove_file(&path);
        assert!(output.status.success());
        let expected = String::from_utf8(output.stdout).unwrap();
        assert_eq!(hex(&actual), expected.split_whitespace().next().unwrap());
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
