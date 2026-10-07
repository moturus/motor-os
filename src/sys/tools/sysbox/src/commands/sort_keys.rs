//! GNU field/byte ranges and ordering modifiers, under byte-order collation.

use std::cmp::Ordering;

#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub reverse: bool,
    pub fold: bool,
    pub numeric: bool,
    pub human: bool,
}

impl Flags {
    pub fn compare(self, left: &[u8], right: &[u8]) -> Ordering {
        let order = if self.numeric || self.human {
            super::numeric::compare(left, right, self.human, self.fold)
        } else if self.fold {
            left.iter()
                .map(u8::to_ascii_uppercase)
                .cmp(right.iter().map(u8::to_ascii_uppercase))
        } else {
            left.cmp(right)
        };
        if self.reverse {
            order.reverse()
        } else {
            order
        }
    }
}

struct Point {
    field: usize,
    character: usize,
    blanks: bool,
}
pub struct Key {
    start: Point,
    end: Option<Point>,
    pub flags: Option<Flags>,
}

fn count<'a>(text: &'a str, label: &str) -> Result<(usize, &'a str), String> {
    let input = text;
    let text = text.trim_start_matches(|character| matches!(character, ' ' | '\t'..='\r'));
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

fn point(
    text: &str,
    start: bool,
    spec: &str,
    flags: &mut Flags,
    explicit: &mut bool,
) -> Result<Point, String> {
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
    let mut blanks = false;
    for flag in rest.chars() {
        *explicit = true;
        match flag {
            'b' => blanks = true,
            'r' => flags.reverse = true,
            'f' => flags.fold = true,
            'n' => flags.numeric = true,
            'h' => flags.human = true,
            _ => return Err(format!("unsupported key option '{flag}' in '{spec}'")),
        }
    }
    Ok(Point {
        field: field - 1,
        character,
        blanks,
    })
}

impl Key {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (start, end) = spec
            .split_once(',')
            .map_or((spec, None), |(start, end)| (start, Some(end)));
        let mut flags = Flags::default();
        let mut explicit = false;
        let start = point(start, true, spec, &mut flags, &mut explicit)?;
        let end = end
            .map(|end| point(end, false, spec, &mut flags, &mut explicit))
            .transpose()?;
        if flags.numeric && flags.human {
            return Err("options '-hn' are incompatible".into());
        }
        Ok(Self {
            start,
            end,
            flags: explicit.then_some(flags),
        })
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
    if point.blanks {
        while position < line.len() && blank(line[position]) {
            position += 1;
        }
    }
    position
        .saturating_add(point.character - usize::from(!end))
        .min(line.len())
}
