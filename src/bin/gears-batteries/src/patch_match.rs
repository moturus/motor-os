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
        // Text with real line breaks was not escaped twice; its `\n` stays literal.
        let (old, new) = if escaped {
            let new = if new.contains(['\n', '\t']) {
                new.to_string()
            } else {
                unescape(new)
            };
            (unescape(old), new)
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
                replacement: if mode == 3 {
                    reindent(source, range.start, &old, &new)
                } else {
                    new
                },
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
        let indent = body.len() - body.trim_start_matches([' ', '\t']).len();
        let skip = if mode >= 3 { indent } else { 0 };
        let mut space = false;
        for (at, ch) in body[skip..].char_indices() {
            let start = offset + skip + at;
            let end = start + ch.len_utf8();
            // Indentation is left to the indentation rule, which re-indents.
            let is_space = matches!(ch, ' ' | '\t') && skip + at >= indent;
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

/// Only the indentation rule ignores leading whitespace, so only it moves
/// `new` by the difference between the matched source line and `old`.
fn reindent(source: &str, start: usize, old: &str, new: &str) -> String {
    let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
    let found = &source[line_start..start];
    if found.len() != indentation(found).len() {
        return new.into();
    }
    let wrote = indentation(old);
    let mut result = String::new();
    for (index, line) in new.split_inclusive('\n').enumerate() {
        let own = indentation(line);
        let body = &line[own.len()..];
        if index == 0 {
            // The source keeps its own indentation before the match.
        } else if body.trim().is_empty() {
            result.push_str(own);
        } else if let Some(deeper) = own.strip_prefix(wrote) {
            result.push_str(found);
            result.push_str(deeper);
        } else if wrote.starts_with(own) {
            let shallower = wrote.len() - own.len();
            result.push_str(&found[..found.len().saturating_sub(shallower)]);
        } else {
            result.push_str(own);
        }
        result.push_str(body);
    }
    result
}

fn indentation(text: &str) -> &str {
    &text[..text.len() - text.trim_start_matches([' ', '\t']).len()]
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
    fn whole_line_edits_keep_relative_indentation() {
        let source = "    if a {\n        b();\n    }\n}\n";
        let (output, rule) = apply(source, "        b();\n    }\n", "        c();\n    }\n");
        assert_eq!(rule, "exact");
        assert_eq!(output, "    if a {\n        c();\n    }\n}\n");
        // Written two levels too shallow: every line moves by the same amount.
        let (output, rule) = apply(source, "    b();\n}\n", "    c();\n      d();\n}\n");
        assert_eq!(rule, "indentation");
        assert_eq!(
            output,
            "    if a {\n        c();\n          d();\n    }\n}\n"
        );
        // Written too deep: lines shallower than the first move up as well.
        let (output, rule) = apply(
            source,
            "            b();\n        }\n",
            "            c();\n        }\n",
        );
        assert_eq!(rule, "indentation");
        assert_eq!(output, "    if a {\n        c();\n    }\n}\n");
    }

    #[test]
    fn escaped_matches_unescape_replacements_only_when_escaped_too() {
        let source = "let a = 1;\nlet b = 2;\n";
        let doubled = apply(source, "let a = 1;\\nlet b = 2;\\n", "let c = 3;\\n").0;
        assert_eq!(doubled, "let c = 3;\n");
        let literal = apply(source, "let a = 1;\\nlet b = 2;\\n", "print!(\"x\\n\");\n").0;
        assert_eq!(literal, "print!(\"x\\n\");\n");
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
