#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEvent {
    Data(Vec<u8>),
    Resize {
        rows: u16,
        columns: u16,
        height_px: u16,
        width_px: u16,
    },
    Disconnect,
}

#[derive(Default)]
pub struct InputFilter {
    control: Vec<u8>,
    at_line_start: bool,
    escape: bool,
}

impl InputFilter {
    pub fn new() -> Self {
        Self {
            at_line_start: true,
            ..Self::default()
        }
    }

    pub fn has_pending_control(&self) -> bool {
        !self.control.is_empty()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<InputEvent> {
        let mut events = Vec::new();
        for byte in bytes {
            if self.control.is_empty() && *byte != 0x1b {
                self.feed_escape(*byte, &mut events);
                continue;
            }
            self.control.push(*byte);
            match parse_control(&self.control) {
                Control::Pending if self.control.len() < 64 => {}
                Control::Consumed(None) => self.control.clear(),
                Control::Consumed(Some(size)) => {
                    self.control.clear();
                    events.push(size);
                }
                Control::Pending | Control::Ordinary => {
                    let pending = std::mem::take(&mut self.control);
                    for byte in pending {
                        self.feed_escape(byte, &mut events);
                    }
                }
            }
        }
        events
    }

    pub fn expire(&mut self) -> Vec<InputEvent> {
        let pending = std::mem::take(&mut self.control);
        let mut events = Vec::new();
        for byte in pending {
            self.feed_escape(byte, &mut events);
        }
        events
    }

    pub fn finish(&mut self) -> Vec<InputEvent> {
        let mut events = self.expire();
        if self.escape {
            self.escape = false;
            push_data(&mut events, b'~');
        }
        events
    }

    fn feed_escape(&mut self, byte: u8, events: &mut Vec<InputEvent>) {
        if self.escape {
            self.escape = false;
            match byte {
                b'.' => events.push(InputEvent::Disconnect),
                b'~' => {
                    push_data(events, b'~');
                    self.at_line_start = false;
                }
                _ => {
                    push_data(events, b'~');
                    push_data(events, byte);
                    self.update_line(byte);
                }
            }
            return;
        }
        if self.at_line_start && byte == b'~' {
            self.escape = true;
            return;
        }
        push_data(events, byte);
        self.update_line(byte);
    }

    fn update_line(&mut self, byte: u8) {
        self.at_line_start = matches!(byte, b'\r' | b'\n');
    }
}

fn push_data(events: &mut Vec<InputEvent>, byte: u8) {
    if let Some(InputEvent::Data(data)) = events.last_mut() {
        data.push(byte);
    } else {
        events.push(InputEvent::Data(vec![byte]));
    }
}

enum Control {
    Pending,
    Ordinary,
    Consumed(Option<InputEvent>),
}

fn parse_control(bytes: &[u8]) -> Control {
    if !bytes.starts_with(b"\x1b[") {
        return if b"\x1b[".starts_with(bytes) {
            Control::Pending
        } else {
            Control::Ordinary
        };
    }
    if bytes.starts_with(b"\x1b[?2048;") || b"\x1b[?2048;".starts_with(bytes) {
        if bytes.ends_with(b"$y") {
            let status = &bytes[b"\x1b[?2048;".len()..bytes.len() - 2];
            return if numeric_field(status) {
                Control::Consumed(None)
            } else {
                Control::Ordinary
            };
        }
        return if bytes[b"\x1b[?2048;".len().min(bytes.len())..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b':' | b'$'))
        {
            Control::Pending
        } else {
            Control::Ordinary
        };
    }
    if bytes.ends_with(b"t") {
        let body = &bytes[2..bytes.len() - 1];
        let fields: Vec<_> = body.split(|byte| *byte == b';').collect();
        if fields.len() < 3 {
            return Control::Ordinary;
        }
        let Some(selector) = field_u16(fields[0]) else {
            return Control::Ordinary;
        };
        if !matches!(selector, 8 | 48) {
            return Control::Ordinary;
        }
        let (Some(rows), Some(columns)) = (field_u16(fields[1]), field_u16(fields[2])) else {
            return Control::Ordinary;
        };
        if rows == 0 || columns == 0 {
            return Control::Ordinary;
        }
        let height_px = fields
            .get(3)
            .and_then(|field| field_u16(field))
            .unwrap_or(0);
        let width_px = fields
            .get(4)
            .and_then(|field| field_u16(field))
            .unwrap_or(0);
        return Control::Consumed(Some(InputEvent::Resize {
            rows,
            columns,
            height_px,
            width_px,
        }));
    }
    if bytes[2..]
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b';' | b':'))
    {
        Control::Pending
    } else {
        Control::Ordinary
    }
}

fn numeric_field(field: &[u8]) -> bool {
    !field.is_empty()
        && field
            .split(|byte| *byte == b':')
            .next()
            .is_some_and(|field| !field.is_empty() && field.iter().all(u8::is_ascii_digit))
}

fn field_u16(field: &[u8]) -> Option<u16> {
    let field = field.split(|byte| *byte == b':').next()?;
    std::str::from_utf8(field).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(events: &[InputEvent]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|event| match event {
                InputEvent::Data(data) => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    #[test]
    fn every_resize_split_is_consumed() {
        let report = b"\x1b[48;24;80;480;1600t";
        for split in 0..=report.len() {
            let mut filter = InputFilter::new();
            let mut events = filter.feed(&report[..split]);
            events.extend(filter.feed(&report[split..]));
            assert_eq!(
                events,
                [InputEvent::Resize {
                    rows: 24,
                    columns: 80,
                    height_px: 480,
                    width_px: 1600,
                }],
                "split {split}"
            );
        }
    }

    #[test]
    fn status_and_text_area_replies_are_consumed() {
        let mut filter = InputFilter::new();
        assert!(filter.feed(b"\x1b[?2048;0$y").is_empty());
        assert_eq!(
            filter.feed(b"\x1b[8;30;100t"),
            [InputEvent::Resize {
                rows: 30,
                columns: 100,
                height_px: 0,
                width_px: 0,
            }]
        );
    }

    #[test]
    fn malformed_overlong_and_expired_prefixes_are_ordinary_bytes() {
        for bytes in [b"\x1b[48;0;80t".as_slice(), b"\x1b[?2048;x$y"] {
            let mut filter = InputFilter::new();
            assert_eq!(data(&filter.feed(bytes)), bytes);
        }
        let mut filter = InputFilter::new();
        assert!(filter.feed(b"\x1b[48;").is_empty());
        assert_eq!(data(&filter.expire()), b"\x1b[48;");
        let overlong = [b"\x1b[".as_slice(), &[b'1'; 70], b"t"].concat();
        let mut filter = InputFilter::new();
        assert_eq!(data(&filter.feed(&overlong)), overlong);
    }

    #[test]
    fn escape_commands_apply_only_at_line_start() {
        let mut filter = InputFilter::new();
        assert_eq!(filter.feed(b"~~x\n"), [InputEvent::Data(b"~x\n".to_vec())]);
        assert_eq!(filter.feed(b"~."), [InputEvent::Disconnect]);

        let mut filter = InputFilter::new();
        assert_eq!(filter.feed(b"x~.\n"), [InputEvent::Data(b"x~.\n".to_vec())]);
        assert!(filter.feed(b"~").is_empty());
        assert_eq!(filter.finish(), [InputEvent::Data(b"~".to_vec())]);
    }
}
