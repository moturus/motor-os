//! Ordered, unique text matching with original-byte positions.

use std::ops::Range;

#[derive(Debug)]
pub struct Match {
    pub range: Range<usize>,
    pub replacement: String,
    pub rule: &'static str,
}

pub fn locate(source: &str, old: &str, new: &str) -> Result<Match, String> {
    if old.is_empty() {
        return Err("old_text must not be empty".into());
    }
    let rules = ["exact", "trailing spaces", "repeated spaces", "indentation"];
    for escaped in [false, true] {
        let (old, new) = if escaped {
            (unescape(old), unescape(new))
        } else {
            (old.to_string(), new.to_string())
        };
        for (mode, rule) in rules.iter().enumerate() {
            let haystack = normalized(source, mode);
            let needle = normalized(&old, mode).text;
            if needle.is_empty() {
                continue;
            }
            let Some(start) = haystack.text.find(&needle) else {
                continue;
            };
            // Search again from the next character, including overlapping hits.
            let after = start + haystack.text[start..].chars().next().unwrap().len_utf8();
            if haystack.text[after..].contains(&needle) {
                return Err(format!("patch is ambiguous using {rule}"));
            }
            let range = haystack.positions[start].0..haystack.positions[start + needle.len() - 1].1;
            return Ok(Match {
                replacement: reindent(source, range.start, &new),
                range,
                rule: if escaped {
                    "escaped newlines/tabs"
                } else {
                    rule
                },
            });
        }
        if unescape(&old) == old {
            break;
        }
    }
    Err("old_text was not found".into())
}

fn unescape(text: &str) -> String {
    text.replace("\\n", "\n").replace("\\t", "\t")
}

struct Normalized {
    text: String,
    positions: Vec<(usize, usize)>,
}

fn normalized(text: &str, mode: usize) -> Normalized {
    let mut result = Normalized {
        text: String::new(),
        positions: Vec::new(),
    };
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let newline = line.ends_with('\n');
        let body = if newline {
            line.strip_suffix("\r\n").unwrap_or(&line[..line.len() - 1])
        } else {
            line
        };
        let body = if mode >= 1 {
            body.trim_end_matches([' ', '\t'])
        } else {
            body
        };
        let skip = if mode >= 3 {
            body.len() - body.trim_start_matches([' ', '\t']).len()
        } else {
            0
        };
        let mut space = false;
        for (at, ch) in body[skip..].char_indices() {
            let start = offset + skip + at;
            let end = start + ch.len_utf8();
            let is_space = matches!(ch, ' ' | '\t');
            if mode >= 2 && is_space && space {
                if let Some(position) = result.positions.last_mut() {
                    position.1 = end;
                }
                continue;
            }
            let ch = if mode >= 2 && is_space { ' ' } else { ch };
            result.text.push(ch);
            result
                .positions
                .extend(std::iter::repeat_n((start, end), ch.len_utf8()));
            space = is_space;
        }
        if newline {
            result.text.push('\n');
            result.positions.push((
                offset + line.len() - if line.ends_with("\r\n") { 2 } else { 1 },
                offset + line.len(),
            ));
        }
        offset += line.len();
    }
    result
}

fn reindent(source: &str, start: usize, new: &str) -> String {
    let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
    let retained = &source[line_start..start];
    if !retained.chars().all(|ch| matches!(ch, ' ' | '\t')) {
        return new.into();
    }
    let rest = &source[line_start..];
    let indent = &rest[..rest.len() - rest.trim_start_matches([' ', '\t']).len()];
    let common = new
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start_matches([' ', '\t']).len())
        .min()
        .unwrap_or(0);
    let mut result = String::new();
    for (index, line) in new.split_inclusive('\n').enumerate() {
        let skip = common.min(line.len() - line.trim_start_matches([' ', '\t']).len());
        if !line.trim().is_empty() {
            result.push_str(if index == 0 {
                &indent[retained.len()..]
            } else {
                indent
            });
        }
        result.push_str(&line[skip..]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(source: &str, old: &str, new: &str) -> (String, &'static str) {
        let matched = locate(source, old, new).unwrap();
        let mut output = source.to_string();
        output.replace_range(matched.range, &matched.replacement);
        (output, matched.rule)
    }

    #[test]
    fn ordered_rules_keep_byte_positions_and_reindent_blocks() {
        for (source, old, rule) in [
            ("prefix α suffix", "α", "exact"),
            ("first  \nsecond\n", "first\nsecond\n", "trailing spaces"),
            ("a   b\n", "a b\n", "repeated spaces"),
            ("    a\n      b\n", "a\nb\n", "indentation"),
            ("a\nb\n", "a\\nb\\n", "escaped newlines/tabs"),
        ] {
            let matched = locate(source, old, "replacement").unwrap();
            assert_eq!(matched.rule, rule);
            assert!(source.is_char_boundary(matched.range.start));
            assert!(source.is_char_boundary(matched.range.end));
        }
        assert_eq!(
            apply("    a\n      b\n", "a\nb\n", "x\n  y\n").0,
            "    x\n      y\n"
        );
        assert_eq!(
            apply("    a\n    b\n", "    a\n    b\n", "    x\n    y\n").0,
            "    x\n    y\n"
        );
        assert_eq!(apply("a\nb\n", "a\\nb\\n", "c\\nd\\n").0, "c\nd\n");
        assert_eq!(apply("a\r\nb\r\n", "a\nb\n", "c\nd\n").0, "c\nd\n");
        assert_eq!(apply("let x = 1;", "1", "2").0, "let x = 2;");
        // Literal escapes stay literal when an exact match succeeds.
        assert_eq!(apply("literal\\n", "literal\\n", "keep\\n").0, "keep\\n");
    }

    #[test]
    fn ambiguity_including_overlaps_and_whitespace_only_patterns_are_refused() {
        for (source, old) in [("aaa", "aa"), ("ααα", "αα"), ("a  b\na   b\n", "a b\n")] {
            assert!(
                locate(source, old, "changed")
                    .unwrap_err()
                    .contains("ambiguous")
            );
        }
        assert!(locate("something", "", "changed").is_err());
        assert!(locate("a\n", " \n \n", "changed").is_err());
        assert!(locate("abc", "not present", "changed").is_err());
    }
}
