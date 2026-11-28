//! The contents of a binary file in a patch, as `git diff --binary` writes them: lines in
//! Git's base 85 that hold zlib data, which is the new file or a delta that makes it.
//!
//! This follows `base85.c`, `apply.c` and `patch-delta.c` of Git.

use gix::bstr::ByteSlice;

/// The most bytes that a file of a binary patch may have.
pub(crate) const MAX_BYTES: usize = 128 * 1024 * 1024;

/// The most bytes that one line of a hunk holds.
pub(crate) const LINE_BYTES: usize = 52;

/// The digits of Git's base 85, in the order of their values.
const DIGITS: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Literal,
    Delta,
}

/// The base-85 layer has been decoded. Keep the zlib stream until this file is checked.
#[derive(Debug)]
pub struct Hunk {
    pub(crate) kind: Kind,
    pub(crate) len: usize,
    pub(crate) compressed: Vec<u8>,
    pub(crate) line: usize,
}

impl Hunk {
    /// Check even an unused direction for corruption, with bounded scratch space.
    pub(crate) fn validate(&self) -> crate::Result {
        self.inflate(|_| {})
    }

    /// Make the file from its other version. A valid delta may still not fit `base`.
    pub(crate) fn apply(&self, base: &[u8]) -> crate::Result<Option<Vec<u8>>> {
        let mut contents = Vec::new();
        contents.try_reserve_exact(self.len)?;
        self.inflate(|chunk| contents.extend_from_slice(chunk))?;
        Ok(match self.kind {
            Kind::Literal => Some(contents),
            Kind::Delta => apply_delta(base, &contents)?,
        })
    }

    fn inflate(&self, mut consume: impl FnMut(&[u8])) -> crate::Result {
        let mut state = gix::zlib::Decompress::new();
        let mut buf = [0; 8192];
        loop {
            let (input, output) = (state.total_in(), state.total_out());
            let Ok(status) = state.decompress(
                &self.compressed[input as usize..],
                &mut buf,
                gix::zlib::FlushDecompress::None,
            ) else {
                break;
            };
            if state.total_out() > self.len as u64 {
                break;
            }
            consume(&buf[..(state.total_out() - output) as usize]);
            if status == gix::zlib::Status::StreamEnd {
                if state.total_out() == self.len as u64 {
                    return Ok(());
                }
                break;
            }
            if state.total_in() == input && state.total_out() == output {
                break;
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("corrupt binary patch at line {}", self.line),
        )
        .into())
    }
}

/// Decode one line of a hunk, without its newline, and add its bytes to `out`.
///
/// The first character is the number of bytes: `A` to `Z` for 1 to 26, `a` to `z` for 27
/// to 52. Groups of five digits follow, each for four bytes. `None` if the line is damaged.
/// The caller makes room for `LINE_BYTES` bytes, so that a line never has to allocate.
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let (&count, groups) = line.split_first()?;
    let mut left = usize::from(match count {
        b'A'..=b'Z' => count - b'A' + 1,
        b'a'..=b'z' => count - b'a' + 27,
        _ => return None,
    });
    // Only the last group may hold bytes that do not count.
    let room = groups.len() / 5 * 4;
    if groups.is_empty() || groups.len() % 5 != 0 || room < left || left + 4 <= room {
        return None;
    }
    for group in groups.as_chunks::<5>().0 {
        let mut value = 0u32;
        for digit in group {
            let digit = DIGITS.find_byte(*digit)? as u32;
            value = value.checked_mul(85)?.checked_add(digit)?;
        }
        let take = left.min(4);
        out.extend_from_slice(&value.to_be_bytes()[..take]);
        left -= take;
    }
    Some(())
}

/// Read a size at the start of a delta: seven bits a byte, the low bits first.
fn delta_size(delta: &mut &[u8]) -> Option<usize> {
    let mut size = 0usize;
    for shift in (0..usize::BITS).step_by(7) {
        let (&byte, rest) = delta.split_first()?;
        *delta = rest;
        size |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(size);
        }
    }
    None
}

/// Apply a delta to `base`. `None` if the delta is damaged, or is one for another file.
fn apply_delta(base: &[u8], mut delta: &[u8]) -> crate::Result<Option<Vec<u8>>> {
    // A delta starts with the size of the file that it is for and of the one it makes.
    let base_len = delta_size(&mut delta);
    let len = delta_size(&mut delta);
    let Some(len) = len.filter(|len| base_len == Some(base.len()) && *len <= MAX_BYTES) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    out.try_reserve_exact(len)?;
    Ok(replay_delta(base, delta, len, out))
}

/// Run the commands of a delta: copies of ranges of `base`, and new bytes in between.
/// `out` has room for the `len` bytes of the file that the delta makes.
fn replay_delta(base: &[u8], mut delta: &[u8], len: usize, mut out: Vec<u8>) -> Option<Vec<u8>> {
    while let Some((&command, rest)) = delta.split_first() {
        delta = rest;
        let chunk = if command & 0x80 != 0 {
            // A copy. The low bits say which bytes of its offset and size follow.
            let mut number = |bits: std::ops::Range<u32>| -> Option<usize> {
                let mut value = 0;
                for (position, bit) in bits.enumerate() {
                    if command & (1 << bit) != 0 {
                        let (&byte, rest) = delta.split_first()?;
                        delta = rest;
                        value |= usize::from(byte) << (8 * position);
                    }
                }
                Some(value)
            };
            let offset = number(0..4)?;
            let size = match number(4..7)? {
                0 => 0x10000,
                size => size,
            };
            base.get(offset..offset.checked_add(size)?)?
        } else {
            // New bytes, as many as the command says. No command is zero.
            let size = usize::from(command);
            if size == 0 || size > delta.len() {
                return None;
            }
            let (bytes, rest) = delta.split_at(size);
            delta = rest;
            bytes
        };
        if chunk.len() > len - out.len() {
            return None;
        }
        out.extend_from_slice(chunk);
    }
    (out.len() == len).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hunk(kind: Kind, lines: &[&str], len: usize) -> Hunk {
        let mut compressed = Vec::new();
        for line in lines {
            decode_line(line.as_bytes(), &mut compressed).unwrap();
        }
        Hunk {
            kind,
            len,
            compressed,
            line: 1,
        }
    }

    // Hunks that Git 2.43 wrote with `git diff --binary`.
    #[test]
    fn hunks_of_git_are_decoded() -> crate::Result {
        let literal = |line, len| hunk(Kind::Literal, &[line], len).apply(&[]);
        assert_eq!(
            literal("QcmYew%ws4i&sXFE01tiwzW@LL", 9)?.unwrap(),
            b"bin\0two!\n"
        );
        assert_eq!(literal("PcmYew%wx#UOXUIp3}pg_", 8)?.unwrap(), b"bin\0one\n");
        assert_eq!(literal("HcmV?d00001", 0)?.unwrap(), b"");

        let record = |n: usize, name: &str| {
            format!("{name} {n:02} \0 some repeated binary payload\n").into_bytes()
        };
        let old: Vec<u8> = (1..=40).flat_map(|n| record(n, "record")).collect();
        let new: Vec<u8> = (1..=40)
            .flat_map(|n| record(n, if n == 20 { "RECORD" } else { "record" }))
            .collect();
        let forward = hunk(Kind::Delta, &["acmaFC^MYpsH#1w1tFwQQ%Vt65aAp8O0tJl#"], 19);
        assert_eq!(forward.apply(&old)?.unwrap(), new);
        let reverse = hunk(Kind::Delta, &["XcmaFC^MYpsH}m8POzfM5n8TO>Gsy(>"], 16);
        assert_eq!(reverse.apply(&new)?.unwrap(), old);
        // A delta is for one file only.
        assert_eq!(forward.apply(&new[1..])?, None);
        Ok(())
    }

    #[test]
    fn damaged_hunks_are_refused() {
        let mut out = Vec::new();
        for line in [
            "",
            "A",
            "A0000",
            "A000000",
            "0cmV?d00001",
            "HcmV?d0000 ",
            "IcmV?d00001",
            "DcmV?d00001",
            "A~~~~~",
        ] {
            assert_eq!(decode_line(line.as_bytes(), &mut out), None, "{line}");
        }
        // The length that a hunk names has to be the length of its data.
        for len in [8, 10] {
            let short_or_long = hunk(Kind::Literal, &["QcmYew%ws4i&sXFE01tiwzW@LL"], len);
            assert!(short_or_long.validate().is_err());
            assert!(short_or_long.apply(&[]).is_err());
        }
        let mut truncated = hunk(Kind::Literal, &["QcmYew%ws4i&sXFE01tiwzW@LL"], 9);
        truncated.compressed.pop();
        assert!(truncated.validate().is_err());
        // Deltas that copy from outside of the file, that are cut off, or that make a
        // file of another length than they say.
        for delta in [
            &[4, 4, 0x91, 2, 3][..],
            &[4, 4, 0x91, 0],
            &[4, 4, 2, b'a'],
            &[4, 2, 0x90, 4],
        ] {
            assert_eq!(apply_delta(b"base", delta).unwrap(), None, "{delta:?}");
        }
        let made = apply_delta(b"base", &[4, 6, 0x90, 4, 2, b'!', b'!']).unwrap();
        assert_eq!(made.unwrap(), b"base!!");
    }
}
