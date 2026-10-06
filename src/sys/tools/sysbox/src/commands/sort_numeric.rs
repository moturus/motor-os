//! Exact decimal-prefix comparison, without floating-point rounding.

use std::cmp::Ordering;

struct Decimal<'a> {
    sign: i8,
    whole: &'a [u8],
    fraction: &'a [u8],
    suffix: u8,
}

fn scan(mut text: &[u8]) -> Decimal<'_> {
    while text
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        text = &text[1..];
    }
    // GNU numeric modes read a decimal prefix, without plus signs or exponents.
    let negative = text.first() == Some(&b'-');
    if negative {
        text = &text[1..];
    }
    let end = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    let mut whole = &text[..end];
    text = &text[end..];
    while whole.first() == Some(&b'0') {
        whole = &whole[1..];
    }
    let mut fraction = &b""[..];
    if text.first() == Some(&b'.') {
        text = &text[1..];
        let end = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
        fraction = &text[..end];
        text = &text[end..];
        while fraction.last() == Some(&b'0') {
            fraction = &fraction[..fraction.len() - 1];
        }
    }
    let sign = if whole.is_empty() && fraction.is_empty() {
        0
    } else if negative {
        -1
    } else {
        1
    };
    Decimal {
        sign,
        whole,
        fraction,
        suffix: text.first().copied().unwrap_or(0),
    }
}

fn power(suffix: u8) -> usize {
    let suffix = if suffix == b'k' { b'K' } else { suffix };
    b"KMGTPEZYRQ"
        .iter()
        .position(|byte| *byte == suffix)
        .map_or(0, |position| position + 1)
}

pub fn compare(left: &[u8], right: &[u8], human: bool, fold: bool) -> Ordering {
    let left = scan(left);
    let right = scan(right);
    let sign = left.sign.cmp(&right.sign);
    if sign != Ordering::Equal || left.sign == 0 {
        return sign;
    }
    let unit = |suffix: u8| {
        if fold {
            suffix.to_ascii_uppercase()
        } else {
            suffix
        }
    };
    // Human sorting compares the suffix rank before the exact mantissa.
    let mut order = if human {
        power(unit(left.suffix)).cmp(&power(unit(right.suffix)))
    } else {
        Ordering::Equal
    };
    if order == Ordering::Equal {
        order = left
            .whole
            .len()
            .cmp(&right.whole.len())
            .then_with(|| left.whole.cmp(right.whole));
    }
    if order == Ordering::Equal {
        let length = left.fraction.len().max(right.fraction.len());
        order = left
            .fraction
            .iter()
            .copied()
            .chain(std::iter::repeat(b'0'))
            .take(length)
            .cmp(
                right
                    .fraction
                    .iter()
                    .copied()
                    .chain(std::iter::repeat(b'0'))
                    .take(length),
            );
    }
    if left.sign < 0 {
        order.reverse()
    } else {
        order
    }
}
