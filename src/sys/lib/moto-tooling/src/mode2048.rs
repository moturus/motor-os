//! Wire helpers for terminal in-band resize notifications (private mode 2048).

#[cfg(not(feature = "std"))]
use alloc::{format, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

pub const ENABLE: &[u8] = b"\x1b[?2048h";
pub const DISABLE: &[u8] = b"\x1b[?2048l";
pub const DECRQM: &[u8] = b"\x1b[?2048$p";
pub const DECRPM_ENABLED: &[u8] = b"\x1b[?2048;1$y";
pub const DECRPM_DISABLED: &[u8] = b"\x1b[?2048;2$y";

/// A canonical mode-2048 control emitted by a terminal application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Enable,
    Disable,
    Query,
}

pub fn decrpm(enabled: bool) -> &'static [u8] {
    if enabled {
        DECRPM_ENABLED
    } else {
        DECRPM_DISABLED
    }
}

/// Build `CSI 48 ; rows ; cols ; height_px ; width_px t`.
pub fn report(rows: u16, cols: u16, height_px: u32, width_px: u32) -> Vec<u8> {
    format!("\x1b[48;{rows};{cols};{height_px};{width_px}t").into_bytes()
}

/// Incrementally recognizes the three canonical controls above.
///
/// Other bytes are copied exactly. A possible prefix is held until it either
/// completes or stops matching; [`Scanner::finish`] returns an incomplete final
/// prefix to the caller rather than losing it.
pub struct Scanner {
    swallow: bool,
    pending: [u8; DECRQM.len()],
    pending_len: usize,
}

impl Scanner {
    pub const fn new(swallow: bool) -> Self {
        Self {
            swallow,
            pending: [0; DECRQM.len()],
            pending_len: 0,
        }
    }

    /// Scan one stream fragment, appending pass-through bytes and commands.
    pub fn feed(&mut self, bytes: &[u8], output: &mut Vec<u8>, commands: &mut Vec<Command>) {
        for byte in bytes {
            self.pending[self.pending_len] = *byte;
            self.pending_len += 1;
            self.resolve(output, commands);
        }
    }

    /// Flush bytes held as a possible but incomplete command prefix.
    pub fn finish(&mut self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.pending[..self.pending_len]);
        self.pending_len = 0;
    }

    fn resolve(&mut self, output: &mut Vec<u8>, commands: &mut Vec<Command>) {
        loop {
            let pending = &self.pending[..self.pending_len];
            if let Some(command) = command(pending) {
                commands.push(command);
                if !self.swallow {
                    output.extend_from_slice(pending);
                }
                self.pending_len = 0;
                return;
            }
            if is_prefix(pending) {
                return;
            }

            output.push(self.pending[0]);
            self.pending.copy_within(1..self.pending_len, 0);
            self.pending_len -= 1;
            if self.pending_len == 0 {
                return;
            }
        }
    }
}

fn command(bytes: &[u8]) -> Option<Command> {
    match bytes {
        ENABLE => Some(Command::Enable),
        DISABLE => Some(Command::Disable),
        DECRQM => Some(Command::Query),
        _ => None,
    }
}

fn is_prefix(bytes: &[u8]) -> bool {
    ENABLE.starts_with(bytes) || DISABLE.starts_with(bytes) || DECRQM.starts_with(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    #[cfg(feature = "std")]
    use std::vec;

    use super::*;

    fn scan(parts: &[&[u8]], swallow: bool) -> (Vec<u8>, Vec<Command>) {
        let mut scanner = Scanner::new(swallow);
        let mut output = Vec::new();
        let mut commands = Vec::new();
        for part in parts {
            scanner.feed(part, &mut output, &mut commands);
        }
        scanner.finish(&mut output);
        (output, commands)
    }

    #[test]
    fn builders_use_protocol_field_order_and_current_state() {
        assert_eq!(decrpm(true), DECRPM_ENABLED);
        assert_eq!(decrpm(false), DECRPM_DISABLED);
        assert_eq!(report(24, 80, 480, 1600), b"\x1b[48;24;80;480;1600t");
    }

    #[test]
    fn controls_are_detected_and_optionally_swallowed() {
        let bytes = [b"before".as_slice(), ENABLE, DECRQM, DISABLE, b"after"];
        let commands = vec![Command::Enable, Command::Query, Command::Disable];

        assert_eq!(
            scan(&bytes, true),
            (b"beforeafter".to_vec(), commands.clone())
        );
        assert_eq!(
            scan(&bytes, false),
            (
                [b"before", ENABLE, DECRQM, DISABLE, b"after"].concat(),
                commands
            )
        );
    }

    #[test]
    fn every_split_point_is_recognized() {
        for (sequence, expected) in [
            (ENABLE, Command::Enable),
            (DISABLE, Command::Disable),
            (DECRQM, Command::Query),
        ] {
            for split in 0..=sequence.len() {
                assert_eq!(
                    scan(&[&sequence[..split], &sequence[split..]], true),
                    (Vec::new(), vec![expected]),
                    "split {split} of {sequence:?}"
                );
            }
        }
    }

    #[test]
    fn false_prefixes_and_overlaps_pass_through_exactly() {
        let bytes = b"\x1b[?2048x\x1b\x1b[?2048$z\x00tail";
        assert_eq!(scan(&[bytes], true), (bytes.to_vec(), Vec::new()));
    }

    #[test]
    fn a_partial_final_sequence_is_returned_by_finish() {
        let bytes = b"text\x1b[?204";
        assert_eq!(scan(&[bytes], true), (bytes.to_vec(), Vec::new()));
    }

    #[test]
    fn one_byte_fragments_and_adjacent_commands_keep_order() {
        let bytes = [ENABLE, DISABLE, ENABLE].concat();
        let parts: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(
            scan(&parts, true),
            (
                Vec::new(),
                vec![Command::Enable, Command::Disable, Command::Enable]
            )
        );
    }
}
