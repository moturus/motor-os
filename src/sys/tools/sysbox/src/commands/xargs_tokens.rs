//! Literal-delimited arguments or xargs' quote-aware whitespace/line records.
use std::io::{BufReader, Read};
fn emit(value: &mut Vec<u8>, accept: &mut impl FnMut(String)) {
    accept(
        String::from_utf8(std::mem::take(value))
            .unwrap_or_else(|_| super::fail("argument is not valid UTF-8")),
    );
}
pub fn arguments(input: impl Read, delimiter: Option<u8>, mut accept: impl FnMut(String)) {
    let mut value = Vec::new();
    let (mut quote, mut escaped, mut active) = (None, false, false);
    let (mut warned, mut truncated) = (false, false);
    for byte in BufReader::new(input).bytes() {
        let byte = byte.unwrap_or_else(|error| super::fail(&format!("read error: {error}")));
        if byte == 0 && delimiter != Some(0) {
            if delimiter.is_none() && !warned {
                eprintln!("xargs: WARNING: a NUL character occurred in the input.  It cannot be passed through in the argument list.  Did you mean to use the --null option?");
                warned = true;
            }
            truncated = true;
            active = true;
            continue;
        }
        if let Some(delimiter) = delimiter {
            if byte == delimiter {
                emit(&mut value, &mut accept);
                active = false;
                truncated = false;
                continue;
            }
            if !truncated {
                value.push(byte);
            }
            active = true;
        } else {
            if escaped {
                escaped = false;
                if !truncated {
                    value.push(byte);
                }
                active = true;
            } else if let Some(quote_byte) = quote {
                if byte == b'\n' {
                    super::fail(if quote_byte == b'\'' {
                        "unmatched single quote; by default quotes are special to xargs unless you use the -0 option"
                    } else {
                        "unmatched double quote; by default quotes are special to xargs unless you use the -0 option"
                    });
                }
                if byte == quote_byte {
                    quote = None;
                } else if !truncated {
                    value.push(byte);
                }
            } else if byte == b'\\' {
                escaped = true;
                active = true;
            } else if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
                active = true;
            } else if matches!(byte, b'\n' | b' ' | b'\t') {
                if active {
                    emit(&mut value, &mut accept);
                }
                active = false;
                truncated = false;
            } else {
                if !truncated {
                    value.push(byte);
                }
                active = true;
            }
        }
        if value.len() >= super::LIMIT {
            super::fail("argument line too long");
        }
    }
    if let Some(quote) = quote.filter(|_| !value.is_empty()) {
        super::fail(if quote == b'\'' {
            "unmatched single quote; by default quotes are special to xargs unless you use the -0 option"
        } else {
            "unmatched double quote; by default quotes are special to xargs unless you use the -0 option"
        });
    }
    if active && (!value.is_empty() || delimiter.is_some()) {
        emit(&mut value, &mut accept);
    }
}
