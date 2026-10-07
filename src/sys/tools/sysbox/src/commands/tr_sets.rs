//! Byte arrays, C-locale classes and ranges used by tr.
pub struct Array {
    pub bytes: Vec<u8>,
    pub classes: Vec<(usize, String)>,
}
fn class(name: &str, byte: u8) -> bool {
    match name {
        "alnum" => byte.is_ascii_alphanumeric(),
        "alpha" => byte.is_ascii_alphabetic(),
        "blank" => matches!(byte, b' ' | b'\t'),
        "cntrl" => byte < 32 || byte == 127,
        "digit" => byte.is_ascii_digit(),
        "graph" => (33..=126).contains(&byte),
        "lower" => byte.is_ascii_lowercase(),
        "print" => (32..=126).contains(&byte),
        "punct" => byte.is_ascii_punctuation(),
        "space" => matches!(byte, b' ' | b'\t'..=b'\r'),
        "upper" => byte.is_ascii_uppercase(),
        "xdigit" => byte.is_ascii_hexdigit(),
        _ => super::fail(&format!("invalid character class '{name}'")),
    }
}
fn byte(input: &[u8], position: &mut usize) -> u8 {
    let byte = input[*position];
    *position += 1;
    if byte != b'\\' {
        return byte;
    }
    if *position == input.len() {
        eprintln!("tr: warning: an unescaped backslash at end of string is not portable");
        return b'\\';
    }
    let escaped = input[*position];
    *position += 1;
    match escaped {
        b'a' => 7,
        b'b' => 8,
        b'f' => 12,
        b'n' => 10,
        b'r' => 13,
        b't' => 9,
        b'v' => 11,
        b'0'..=b'7' => {
            let mut number = (escaped - b'0') as u16;
            for _ in 0..2 {
                if let Some(digit @ b'0'..=b'7') = input.get(*position) {
                    let next = number * 8 + (digit - b'0') as u16;
                    if next > 255 {
                        break;
                    }
                    number = next;
                    *position += 1;
                } else {
                    break;
                }
            }
            number as u8
        }
        other => other,
    }
}
impl Array {
    pub fn parse(text: &str) -> Self {
        let input = text.as_bytes();
        let mut array = Self {
            bytes: Vec::new(),
            classes: Vec::new(),
        };
        let mut position = 0;
        while position < input.len() {
            let rest = &input[position..];
            if rest.starts_with(b"[:") {
                if let Some(end) = rest[2..].windows(2).position(|p| p == b":]") {
                    let end = end + 2;
                    if end == 2 {
                        super::fail("missing character class name '[::]'");
                    }
                    let name = std::str::from_utf8(&rest[2..end])
                        .unwrap_or_else(|_| super::fail("invalid character class"));
                    array.classes.push((array.bytes.len(), name.to_owned()));
                    array.bytes.extend((0..=255).filter(|b| class(name, *b)));
                    position += end + 2;
                    continue;
                }
            }
            let repetition = if rest.starts_with(b"[") && rest.contains(&b']') {
                let mut marker = 1;
                byte(rest, &mut marker);
                rest.get(marker) == Some(&b'*') && rest[marker + 1..].contains(&b']')
            } else {
                false
            };
            let equivalence =
                rest.starts_with(b"[=") && rest[2..].windows(2).any(|pair| pair == b"=]");
            if equivalence || repetition {
                super::fail("unsupported equivalence or repetition construct");
            }
            let first = byte(input, &mut position);
            if input.get(position) == Some(&b'-') && position + 1 < input.len() {
                position += 1;
                let last = byte(input, &mut position);
                if last < first {
                    super::fail(&format!(
                        "range-endpoints of '{}-{}' are in reverse collating sequence order",
                        first as char, last as char
                    ));
                }
                array.bytes.extend(first..=last);
            } else {
                array.bytes.push(first);
            }
        }
        array
    }
    pub fn members(&self) -> [bool; 256] {
        let mut members = [false; 256];
        for byte in &self.bytes {
            members[*byte as usize] = true;
        }
        members
    }
}
