//! Streaming rnetbench server protocol over a netstack TCP socket.
//! Its framing matches src/bin/rnetbench; no host kernel TCP endpoint is used.
const CLIENT: &[u8] = b"rnetbench_magic_client";
const SERVER: &[u8] = b"rnetbench_magic_server";
static PATTERN: [u8; 65_792] = {
    let mut bytes = [0; 65_792];
    let mut i = 0;
    while i < bytes.len() {
        bytes[i] = i as u8;
        i += 1;
    }
    bytes
};

enum Phase {
    Greeting,
    Reply,
    Header,
    FlowHeader,
    EchoRead,
    EchoWrite,
    Upload,
    Download,
    FlowDone,
    Failed,
}

pub struct Session {
    phase: Phase,
    bytes: [u8; 64],
    used: usize,
    sent: usize,
    offset: usize,
    buffer_size: usize,
    remaining: Option<usize>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            phase: Phase::Greeting,
            bytes: [0; 64],
            used: 0,
            sent: 0,
            offset: 0,
            buffer_size: 64,
            remaining: None,
        }
    }
}

impl Session {
    pub fn handshaking(&self) -> bool {
        matches!(
            self.phase,
            Phase::Greeting | Phase::Reply | Phase::Header | Phase::FlowHeader
        )
    }

    pub fn failed(&self) -> bool {
        matches!(self.phase, Phase::Failed)
    }

    /// Consume only bytes for the current phase; TCP retains the rest until
    /// the greeting/echo response has drained. Storage never grows with input.
    pub fn receive(&mut self, input: &[u8]) -> usize {
        let target = match self.phase {
            Phase::Greeting => CLIENT.len(),
            Phase::Header => 16,
            Phase::FlowHeader => 8,
            Phase::EchoRead => 64,
            Phase::Upload => {
                let count = input.len().min(self.buffer_size).min(65_536);
                if input[..count] != PATTERN[self.offset..self.offset + count] {
                    self.phase = Phase::Failed;
                }
                self.offset = (self.offset + count) & 255;
                return count;
            }
            _ => return 0,
        };
        let count = input.len().min(target - self.used);
        self.bytes[self.used..self.used + count].copy_from_slice(&input[..count]);
        self.used += count;
        if self.used != target {
            return count;
        }
        self.used = 0;
        self.phase = match self.phase {
            Phase::Greeting if self.bytes[..CLIENT.len()] == *CLIENT => Phase::Reply,
            Phase::Header => {
                let command = u64::from_le_bytes(self.bytes[..8].try_into().unwrap());
                let size = u64::from_le_bytes(self.bytes[8..16].try_into().unwrap());
                if !(64..=1_048_576).contains(&size) {
                    Phase::Failed
                } else {
                    self.buffer_size = size as usize;
                    match command {
                        1 => Phase::EchoRead,
                        2 => Phase::Upload,
                        3 => Phase::Download,
                        4 => Phase::FlowHeader,
                        _ => Phase::Failed,
                    }
                }
            }
            Phase::FlowHeader => {
                let total = u64::from_le_bytes(self.bytes[..8].try_into().unwrap());
                if !(1024..=16_777_216).contains(&total) {
                    Phase::Failed
                } else {
                    self.remaining = Some(total as usize);
                    Phase::Download
                }
            }
            Phase::EchoRead => Phase::EchoWrite,
            _ => Phase::Failed,
        };
        count
    }

    pub fn output(&self, capacity: usize) -> &[u8] {
        let data = match self.phase {
            Phase::Reply => &SERVER[self.sent..],
            Phase::EchoWrite => &self.bytes[self.sent..],
            Phase::Download => {
                let count = self
                    .remaining
                    .unwrap_or(self.buffer_size)
                    .min(self.buffer_size)
                    .min(65_536);
                &PATTERN[self.offset..self.offset + count]
            }
            _ => &[],
        };
        &data[..capacity.min(data.len())]
    }

    pub fn sent(&mut self, count: usize) {
        assert!(count <= self.output(usize::MAX).len());
        match self.phase {
            Phase::Reply | Phase::EchoWrite => {
                self.sent += count;
                let target = if matches!(self.phase, Phase::Reply) {
                    SERVER.len()
                } else {
                    64
                };
                if self.sent == target {
                    self.sent = 0;
                    self.phase = if matches!(self.phase, Phase::Reply) {
                        Phase::Header
                    } else {
                        Phase::EchoRead
                    };
                }
            }
            Phase::Download => {
                self.offset = (self.offset + count) & 255;
                if let Some(remaining) = &mut self.remaining {
                    *remaining -= count;
                    if *remaining == 0 {
                        self.phase = Phase::FlowDone;
                    }
                }
            }
            _ => assert_eq!(count, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(command: u64, size: u64) -> Session {
        let mut session = Session::default();
        for byte in CLIENT {
            assert_eq!(session.receive(&[*byte]), 1);
        }
        assert_eq!(session.receive(&[0; 16]), 0); // Must answer before reading header.
        let mut reply = Vec::new();
        while !session.output(1).is_empty() {
            reply.extend_from_slice(session.output(1));
            session.sent(1);
        }
        assert_eq!(reply, SERVER);
        for byte in command.to_le_bytes().into_iter().chain(size.to_le_bytes()) {
            assert_eq!(session.receive(&[byte]), 1);
        }
        session
    }

    #[test]
    fn fragmented_handshake_and_round_trips() {
        let mut session = start(1, 1024);
        for value in 0..8 {
            for _ in 0..64 {
                assert_eq!(session.receive(&[value]), 1);
            }
            assert_eq!(session.receive(&[99]), 0);
            for expected in [17, 17, 17, 13] {
                assert_eq!(session.output(17), &vec![value; expected]);
                session.sent(expected);
            }
        }
        assert!(!session.failed());
    }

    #[test]
    fn throughput_and_exact_flow_patterns() {
        let mut upload = start(2, 65_536);
        let mut download = start(3, 65_536);
        for size in [1, 255, 4097, 65_536, 23] {
            let data = download.output(size);
            assert_eq!(data.len(), size);
            assert_eq!(upload.receive(data), size);
            download.sent(size);
        }
        assert!(!upload.failed());
        assert_eq!(upload.receive(&[0xff; 4]), 4);
        assert!(upload.failed());
        let mut flow = start(4, 1024);
        assert_eq!(flow.receive(&8193_u64.to_le_bytes()), 8);
        let mut total = 0;
        while !flow.output(777).is_empty() {
            let bytes = flow.output(777);
            for (index, byte) in bytes.iter().enumerate() {
                assert_eq!(*byte, (total + index) as u8);
            }
            let count = bytes.len();
            total += count;
            flow.sent(count);
        }
        assert_eq!(total, 8193);
        assert!(!flow.failed()); // Wait for client FIN; do not close first.
    }

    #[test]
    fn requested_buffer_limits_throughput_and_flow_io() {
        let mut upload = start(2, 64);
        let mut download = start(3, 64);
        for offset in (0..256).step_by(64) {
            assert_eq!(download.output(65_536), &PATTERN[offset..offset + 64]);
            assert_eq!(upload.receive(&PATTERN[offset..offset + 128]), 64);
            download.sent(64);
        }
        assert!(!upload.failed());
        let mut flow = start(4, 64);
        flow.receive(&1025_u64.to_le_bytes());
        let mut total = 0;
        while !flow.output(65_536).is_empty() {
            let bytes = flow.output(65_536);
            assert_eq!(bytes.len(), (1025_usize - total).min(64));
            let count = bytes.len();
            total += count;
            flow.sent(count);
        }
        assert_eq!(total, 1025);
    }

    #[test]
    fn rejects_bad_greetings_commands_and_sizes() {
        let mut bad = Session::default();
        assert_eq!(bad.receive(&[0; 64]), CLIENT.len());
        assert!(bad.failed());
        for (command, size) in [(0, 64), (5, 64), (1, 63), (1, 1_048_577)] {
            assert!(start(command, size).failed());
        }
        for total in [0_u64, 16_777_217] {
            let mut flow = start(4, 1024);
            flow.receive(&total.to_le_bytes());
            assert!(flow.failed());
        }
    }
}
