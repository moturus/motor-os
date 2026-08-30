const ESC: u8 = 0x1b;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    String { bel_terminates: bool },
    StringEscape { bel_terminates: bool },
}

pub(crate) struct Scanner {
    state: State,
    utf8_remaining: u8,
    utf8_lead: u8,
}

impl Scanner {
    pub(crate) const fn new() -> Self {
        Self {
            state: State::Ground,
            utf8_remaining: 0,
            utf8_lead: 0,
        }
    }

    pub(crate) fn is_safe(&self) -> bool {
        self.state == State::Ground && self.utf8_remaining == 0
    }

    pub(crate) fn advance(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.advance_byte(byte);
        }
    }

    pub(crate) fn cancel(&mut self) {
        self.advance(&[CAN]);
        debug_assert!(self.is_safe());
    }

    fn advance_byte(&mut self, byte: u8) {
        if byte == CAN || byte == SUB {
            self.utf8_remaining = 0;
            self.state = State::Ground;
            return;
        }

        if self.utf8_remaining != 0 {
            if byte & 0xc0 == 0x80 {
                self.utf8_remaining -= 1;
                if self.utf8_remaining == 0
                    && self.utf8_lead == 0xc2
                    && (0x80..=0x9f).contains(&byte)
                {
                    self.advance_c1(byte);
                }
                return;
            }
            self.utf8_remaining = 0;
        }

        match byte {
            0xc2..=0xdf => {
                self.utf8_lead = byte;
                self.utf8_remaining = 1;
            }
            0xe0..=0xef => {
                self.utf8_lead = byte;
                self.utf8_remaining = 2;
            }
            0xf0..=0xf4 => {
                self.utf8_lead = byte;
                self.utf8_remaining = 3;
            }
            0x80..=0x9f => self.advance_c1(byte),
            _ => self.advance_ascii(byte),
        }
    }

    fn advance_c1(&mut self, byte: u8) {
        match self.state {
            State::String { .. } | State::StringEscape { .. } if byte == 0x9c => {
                self.state = State::Ground;
            }
            State::Ground => {
                self.state = match byte {
                    0x90 => State::String {
                        bel_terminates: false,
                    },
                    0x98 | 0x9e | 0x9f => State::String {
                        bel_terminates: false,
                    },
                    0x9b => State::Csi,
                    0x9d => State::String {
                        bel_terminates: true,
                    },
                    _ => State::Ground,
                };
            }
            _ => {}
        }
    }

    fn advance_ascii(&mut self, byte: u8) {
        self.state = match self.state {
            State::Ground => {
                if byte == ESC {
                    State::Escape
                } else {
                    State::Ground
                }
            }
            State::Escape => match byte {
                ESC => State::Escape,
                b'[' => State::Csi,
                b']' => State::String {
                    bel_terminates: true,
                },
                b'P' | b'X' | b'^' | b'_' => State::String {
                    bel_terminates: false,
                },
                0x20..=0x2f => State::EscapeIntermediate,
                0x30..=0x7e => State::Ground,
                _ => State::Escape,
            },
            State::EscapeIntermediate => match byte {
                ESC => State::Escape,
                0x20..=0x2f => State::EscapeIntermediate,
                0x30..=0x7e => State::Ground,
                _ => State::EscapeIntermediate,
            },
            State::Csi => match byte {
                ESC => State::Escape,
                0x40..=0x7e => State::Ground,
                _ => State::Csi,
            },
            State::String { bel_terminates } => {
                if byte == ESC {
                    State::StringEscape { bel_terminates }
                } else if bel_terminates && byte == 0x07 {
                    State::Ground
                } else {
                    State::String { bel_terminates }
                }
            }
            State::StringEscape { bel_terminates } => match byte {
                b'\\' => State::Ground,
                0x07 if bel_terminates => State::Ground,
                ESC => State::StringEscape { bel_terminates },
                _ => State::String { bel_terminates },
            },
        };
    }
}

pub(crate) fn run_self_tests() {
    let sequences: &[&[u8]] = &[
        b"\x1b(B",
        b"\x1b[31m",
        b"\x1b]title\x07",
        b"\x1b]title\x1b\\",
        b"\x1b]title\x1b\x07",
        b"\x1bPdata\x1b\\",
        b"\x1bXdata\x1b\\",
        b"\x1b^data\x1b\\",
        b"\x1b_data\x1b\\",
    ];
    for sequence in sequences {
        for split in 1..sequence.len() {
            let mut scanner = Scanner::new();
            scanner.advance(&sequence[..split]);
            assert!(
                !scanner.is_safe(),
                "unsafe prefix became safe: {sequence:?}"
            );
            scanner.advance(&sequence[split..]);
            assert!(
                scanner.is_safe(),
                "complete sequence stayed unsafe: {sequence:?}"
            );
        }
    }

    let mut scanner = Scanner::new();
    scanner.advance(&[0xc3]);
    assert!(!scanner.is_safe());
    scanner.advance(&[0xa9]);
    assert!(scanner.is_safe());

    scanner.advance(&[0xc2, 0x9b, b'3']);
    assert!(!scanner.is_safe());
    scanner.advance(b"1m");
    assert!(scanner.is_safe());

    scanner.advance(b"\x1b]title\xc2");
    assert!(!scanner.is_safe());
    scanner.advance(&[0x9c]);
    assert!(scanner.is_safe());

    scanner.advance(&[0xe2]);
    assert!(!scanner.is_safe());
    scanner.advance(b"A");
    assert!(scanner.is_safe());

    scanner.advance(b"\x1b[");
    scanner.cancel();
    assert!(scanner.is_safe());

    println!("sys-tty ANSI scanner self-test PASS");
}
