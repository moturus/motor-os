//! In-crate pattern matching and pathname expansion (Phase 3).
//!
//! Two related pieces, no external `glob`/`fnmatch` crates (portability is the
//! whole point of the project):
//!
//! - [`fnmatch`] — POSIX pattern matching (`*`, `?`, `[…]` bracket expressions),
//!   reused for `case` patterns and `${x#pat}`-style trimming.
//! - [`glob`] — pathname expansion: match a pattern against the filesystem,
//!   honoring the leading-`.` rule and returning sorted matches (empty when none,
//!   so the caller can leave the word literal per POSIX §2.13.3).
//!
//! Patterns use `\c` to mean a literal `c`: the expansion engine escapes quoted
//! characters that way so that only *unquoted* `*`/`?`/`[` are special. Bracket
//! character classes (`[:alpha:]`) and collation ranges beyond plain ASCII are
//! deferred (see the plan's skip list).

use std::path::Path;

/// Does `text` match the shell pattern `pattern`? `\c` escapes a literal `c`.
pub fn fnmatch(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    match_here(&p, &t)
}

/// Is any `*`/`?`/`[` in `s` unescaped (i.e. does `s` need pathname expansion)?
pub fn has_magic(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2, // skip the escaped char
            '*' | '?' | '[' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Remove `\c` escapes, yielding the literal string (used when a pattern has no
/// filesystem match and must be left as a literal word).
pub fn unescape(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn match_here(p: &[char], t: &[char]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    loop {
        if pi == p.len() {
            return ti == t.len();
        }
        match p[pi] {
            '*' => {
                while pi < p.len() && p[pi] == '*' {
                    pi += 1;
                }
                if pi == p.len() {
                    return true; // trailing * matches the rest
                }
                for k in ti..=t.len() {
                    if match_here(&p[pi..], &t[k..]) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if ti == t.len() {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            '[' => match match_class(&p[pi..], t.get(ti).copied()) {
                Some((matched, consumed)) => {
                    if !matched {
                        return false;
                    }
                    pi += consumed;
                    ti += 1;
                }
                None => {
                    // Unterminated `[` is a literal `[`.
                    if ti == t.len() || t[ti] != '[' {
                        return false;
                    }
                    pi += 1;
                    ti += 1;
                }
            },
            '\\' => {
                let (lit, adv) = if pi + 1 < p.len() {
                    (p[pi + 1], 2)
                } else {
                    ('\\', 1)
                };
                if ti == t.len() || t[ti] != lit {
                    return false;
                }
                pi += adv;
                ti += 1;
            }
            c => {
                if ti == t.len() || t[ti] != c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
}

/// Match `ch` against a bracket expression beginning at `p[0] == '['`. Returns
/// `(matched, chars_consumed)` including the closing `]`, or `None` if the
/// bracket is unterminated (so the caller treats `[` literally).
fn match_class(p: &[char], ch: Option<char>) -> Option<(bool, usize)> {
    let mut i = 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '!' || p[i] == '^') {
        negate = true;
        i += 1;
    }
    let members_start = i;
    let mut matched = false;
    while i < p.len() {
        if p[i] == ']' && i > members_start {
            // closing bracket
            let is_match = ch.is_some() && (matched ^ negate);
            return Some((is_match, i + 1));
        }
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            // range a-z
            if let Some(c) = ch
                && p[i] <= c
                && c <= p[i + 2]
            {
                matched = true;
            }
            i += 3;
        } else {
            if Some(p[i]) == ch {
                matched = true;
            }
            i += 1;
        }
    }
    None // no closing ]
}

/// Pathname expansion: return the sorted list of existing paths matching
/// `pattern` (empty if none). `\c` escapes keep quoted metacharacters literal.
pub fn glob(pattern: &str) -> Vec<String> {
    if pattern.is_empty() {
        return Vec::new();
    }
    let absolute = pattern.starts_with('/');
    let dir_only = pattern.len() > 1 && pattern.ends_with('/');

    let comps: Vec<String> = pattern
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_string())
        .collect();
    if comps.is_empty() {
        // Pattern is only slashes (e.g. "/"): a literal path, nothing to glob.
        return Vec::new();
    }

    let mut results = Vec::new();
    let base = if absolute { "/" } else { "" };
    expand_components(base, &comps, &mut results);

    if dir_only {
        results.retain(|p| Path::new(p).is_dir());
        for p in &mut results {
            p.push('/');
        }
    }
    results.sort();
    results
}

fn join(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        "/" => format!("/{name}"),
        _ => format!("{dir}/{name}"),
    }
}

fn expand_components(dir: &str, comps: &[String], results: &mut Vec<String>) {
    let (comp, rest) = comps.split_first().expect("non-empty comps");

    if !has_magic(comp) {
        // A literal path element: descend without listing the directory.
        let path = join(dir, &unescape(comp));
        if rest.is_empty() {
            if Path::new(&path).exists() {
                results.push(path);
            }
        } else if Path::new(&path).is_dir() {
            expand_components(&path, rest, results);
        }
        return;
    }

    let read_from = if dir.is_empty() { "." } else { dir };
    let match_dotfiles = unescape(comp).starts_with('.');
    let mut names: Vec<String> = match std::fs::read_dir(read_from) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| (match_dotfiles || !name.starts_with('.')) && fnmatch(comp, name))
            .collect(),
        Err(_) => return,
    };
    names.sort();

    for name in names {
        let path = join(dir, &name);
        if rest.is_empty() {
            results.push(path);
        } else if Path::new(&path).is_dir() {
            expand_components(&path, rest, results);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fnmatch, glob, has_magic, unescape};

    #[test]
    fn star_and_question() {
        assert!(fnmatch("*", "anything"));
        assert!(fnmatch("*", ""));
        assert!(fnmatch("a*c", "abbbc"));
        assert!(fnmatch("a*c", "ac"));
        assert!(!fnmatch("a*c", "abcd"));
        assert!(fnmatch("?", "x"));
        assert!(!fnmatch("?", "xy"));
        assert!(fnmatch("a?c", "abc"));
    }

    #[test]
    fn brackets() {
        assert!(fnmatch("[abc]", "b"));
        assert!(!fnmatch("[abc]", "d"));
        assert!(fnmatch("[a-z]", "m"));
        assert!(!fnmatch("[a-z]", "M"));
        assert!(fnmatch("[!a-z]", "M")); // negation
        assert!(fnmatch("[^0-9]", "a"));
        assert!(fnmatch("x[0-9]y", "x5y"));
        // A `]` as the first member is literal.
        assert!(fnmatch("[]a]", "]"));
        // Unterminated bracket is a literal `[`.
        assert!(fnmatch("[abc", "[abc"));
    }

    #[test]
    fn escapes() {
        assert!(fnmatch("a\\*b", "a*b"));
        assert!(!fnmatch("a\\*b", "axb"));
        assert!(!has_magic("a\\*b"));
        assert!(has_magic("a*b"));
        assert!(has_magic("f[oo]"));
        assert_eq!(unescape("a\\*b\\?"), "a*b?");
    }

    #[test]
    fn glob_matches_real_files() {
        let dir = std::env::temp_dir().join(format!("rush_glob_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["a.txt", "b.txt", "c.log", ".hidden"] {
            std::fs::write(dir.join(name), "").unwrap();
        }

        let base = dir.to_str().unwrap();
        let mut got = glob(&format!("{base}/*.txt"));
        got.sort();
        assert_eq!(
            got,
            vec![format!("{base}/a.txt"), format!("{base}/b.txt")]
        );

        // Leading-dot files are not matched by a leading `*`.
        let all = glob(&format!("{base}/*"));
        assert!(!all.iter().any(|p| p.ends_with(".hidden")));

        // No match returns empty (caller keeps the literal word).
        assert!(glob(&format!("{base}/*.zzz")).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
