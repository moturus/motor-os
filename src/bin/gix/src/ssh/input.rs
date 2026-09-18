use std::{
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub(super) const DISCOVERY_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const SESSION_BYTES: u64 = 128 * 1024 * 1024;

/// Count wire bytes before Gitoxide's metadata parsers can retain them.
pub(super) struct Input<R> {
    reader: R,
    limit: Arc<AtomicU64>,
    consumed: u64,
    exceeded: bool,
}

impl<R> Input<R> {
    pub(super) fn new(reader: R, limit: Arc<AtomicU64>) -> Self {
        Self {
            reader,
            limit,
            consumed: 0,
            exceeded: false,
        }
    }
}

impl<R: Read> Read for Input<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let limit = self.limit.load(Ordering::Relaxed);
        let allowed = (limit.saturating_sub(self.consumed)).min(out.len() as u64) as usize;
        if allowed == 0 || self.exceeded {
            // The session supervisor can kill SSH if this EOF check blocks.
            if !self.exceeded && self.reader.read(&mut [0])? == 0 {
                return Ok(0);
            }
            self.exceeded = true;
            return Err(io::Error::other(format!(
                "SSH response exceeded the {limit}-byte limit"
            )));
        }
        let count = self.reader.read(&mut out[..allowed])?;
        self.consumed += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_bytes_before_delivery_and_does_not_reset_at_first_request() -> io::Result<()> {
        let limit = Arc::new(AtomicU64::new(3));
        let mut reader = Input::new(b"abcdef".as_slice(), limit.clone());
        let mut bytes = [0; 8];
        assert_eq!(reader.read(&mut bytes)?, 3);
        assert_eq!(&bytes[..3], b"abc");
        limit.store(5, Ordering::Relaxed);
        assert_eq!(reader.read(&mut bytes)?, 2);
        assert_eq!(&bytes[..2], b"de");
        assert!(reader.read(&mut bytes).is_err());
        assert!(reader.read(&mut bytes).is_err());
        assert_eq!(reader.read(&mut [])?, 0);

        let mut exact = Input::new(b"abc".as_slice(), Arc::new(AtomicU64::new(3)));
        assert_eq!(exact.read(&mut bytes)?, 3);
        assert_eq!(exact.read(&mut bytes)?, 0);
        Ok(())
    }
}
