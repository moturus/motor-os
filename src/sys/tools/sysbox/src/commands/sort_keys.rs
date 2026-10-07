//! GNU field and byte ranges under byte-order collation.

struct Point {
    field: usize,
    character: usize,
}
pub struct Key {
    start: Point,
    end: Option<Point>,
}

fn count<'a>(text: &'a str, label: &str) -> Result<(usize, &'a str), String> {
    let input = text;
    let text = text.trim_ascii_start();
    let text = text.strip_prefix('+').unwrap_or(text);
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(format!("{label}: invalid count at start of '{input}'"));
    }
    let number = text.as_bytes()[..digits]
        .iter()
        .fold(0usize, |number, byte| {
            number
                .saturating_mul(10)
                .saturating_add((byte - b'0') as usize)
        });
    Ok((number, &text[digits..]))
}

fn point(text: &str, start: bool, spec: &str) -> Result<Point, String> {
    let (field, rest) = count(
        text,
        if start {
            "invalid number at field start"
        } else {
            "invalid number after ','"
        },
    )?;
    let (character, rest) = if let Some(rest) = rest.strip_prefix('.') {
        count(rest, "invalid number after '.'")?
    } else {
        (usize::from(start), rest)
    };
    let invalid = if field == 0 {
        Some("field number is zero")
    } else if start && character == 0 {
        Some("character offset is zero")
    } else {
        None
    };
    if let Some(reason) = invalid {
        return Err(format!("{reason}: invalid field specification '{spec}'"));
    }
    if let Some(flag) = rest.chars().next() {
        return Err(format!("unsupported key option '{flag}' in '{spec}'"));
    }
    Ok(Point {
        field: field - 1,
        character,
    })
}

impl Key {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (start, end) = spec
            .split_once(',')
            .map_or((spec, None), |(start, end)| (start, Some(end)));
        let start = point(start, true, spec)?;
        let end = end.map(|end| point(end, false, spec)).transpose()?;
        Ok(Self { start, end })
    }

    pub fn slice<'a>(&self, line: &'a [u8], delimiter: Option<u8>) -> &'a [u8] {
        let start = position(line, &self.start, false, delimiter);
        let end = self
            .end
            .as_ref()
            .map_or(line.len(), |end| position(line, end, true, delimiter));
        &line[start..end.max(start)]
    }
}

fn blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn field_end(line: &[u8], mut position: usize, delimiter: Option<u8>) -> usize {
    if let Some(delimiter) = delimiter {
        return line[position..]
            .iter()
            .position(|byte| *byte == delimiter)
            .map_or(line.len(), |end| position + end);
    }
    while position < line.len() && blank(line[position]) {
        position += 1;
    }
    while position < line.len() && !blank(line[position]) {
        position += 1;
    }
    position
}

fn position(line: &[u8], point: &Point, end: bool, delimiter: Option<u8>) -> usize {
    let mut position = 0;
    for _ in 0..point.field {
        position = field_end(line, position, delimiter);
        if position == line.len() {
            return position;
        }
        position += usize::from(delimiter.is_some());
    }
    if end && point.character == 0 {
        return field_end(line, position, delimiter);
    }
    position
        .saturating_add(point.character - usize::from(!end))
        .min(line.len())
}
