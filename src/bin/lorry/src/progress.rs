use std::fmt;
use std::io::{self, Write};

use crate::diagnostic::{Error, Result};

#[derive(Clone, Copy)]
pub struct Progress {
    enabled: bool,
}

impl Progress {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn report(&self, message: impl fmt::Display) -> Result<()> {
        self.write_to(&mut io::stderr().lock(), message)
    }

    fn write_to(&self, output: &mut impl Write, message: impl fmt::Display) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        writeln!(output, "{message}")
            .and_then(|()| output.flush())
            .map_err(|error| Error::failure(format!("failed to write progress: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Output {
        bytes: Vec<u8>,
        flushed: bool,
    }

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn enabled_progress_writes_and_flushes_each_line() {
        let mut output = Output {
            bytes: Vec::new(),
            flushed: false,
        };
        Progress::new(true)
            .write_to(&mut output, "Downloading demo v1.0.0")
            .unwrap();

        assert_eq!(output.bytes, b"Downloading demo v1.0.0\n");
        assert!(output.flushed);
    }

    #[test]
    fn disabled_progress_writes_nothing() {
        let mut output = Output {
            bytes: Vec::new(),
            flushed: false,
        };
        Progress::new(false)
            .write_to(&mut output, "hidden")
            .unwrap();

        assert!(output.bytes.is_empty());
        assert!(!output.flushed);
    }
}
