//! Portable search primitives shared by native search and optional accelerators.

use std::borrow::Cow;

use regex::RegexBuilder;

use crate::config::Resources;

/// One bounded pattern with identical literal and regular-expression modes.
pub struct Matcher(regex::Regex);

impl Matcher {
    pub fn new(
        pattern: &str,
        regular_expression: bool,
        ignore_case: bool,
        resources: Resources,
    ) -> Result<Matcher, String> {
        let source = if regular_expression {
            Cow::Borrowed(pattern)
        } else {
            Cow::Owned(regex::escape(pattern))
        };
        let nest_limit = u32::try_from(resources.regex_nest_limit)
            .map_err(|_| "resources.regex_nest_limit exceeds the regex engine limit".to_string())?;
        let compiled = RegexBuilder::new(&source)
            .case_insensitive(ignore_case)
            .size_limit(resources.regex_size_limit_bytes)
            .dfa_size_limit(resources.regex_dfa_size_limit_bytes)
            .nest_limit(nest_limit)
            .build()
            .map_err(|error| format!("bad regular expression: {error}"))?;
        Ok(Matcher(compiled))
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.0.is_match(text)
    }
}

/// Include/exclude globs compiled through the same bounded engine as search.
pub struct FileFilter {
    include: Option<Matcher>,
    exclude: Option<Matcher>,
}

impl FileFilter {
    pub fn new(
        includes: &[String],
        excludes: &[String],
        resources: Resources,
    ) -> Result<FileFilter, String> {
        Ok(FileFilter {
            include: compile_globs(includes, resources)?,
            exclude: compile_globs(excludes, resources)?,
        })
    }

    pub fn accepts(&self, path: &str) -> bool {
        self.include.as_ref().is_none_or(|glob| glob.is_match(path))
            && self
                .exclude
                .as_ref()
                .is_none_or(|glob| !glob.is_match(path))
    }
}

fn compile_globs(patterns: &[String], resources: Resources) -> Result<Option<Matcher>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.iter().any(String::is_empty) {
        return Err("glob patterns must not be empty".to_string());
    }
    let alternatives: Vec<String> = patterns.iter().map(|glob| glob_source(glob)).collect();
    let source = format!("^(?:{})$", alternatives.join("|"));
    Matcher::new(&source, true, false, resources).map(Some)
}

/// `*` and `?` stay inside a path component; `**` crosses directories.
fn glob_source(glob: &str) -> String {
    let mut source = String::new();
    if !glob.contains('/') {
        source.push_str("(?:.*/)?");
    }
    let mut chars = glob.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                if chars.peek() == Some(&'/') {
                    chars.next();
                    source.push_str("(?:.*/)?");
                } else {
                    source.push_str(".*");
                }
            }
            '*' => source.push_str("[^/]*"),
            '?' => source.push_str("[^/]"),
            ch => source.push_str(&regex::escape(&ch.to_string())),
        }
    }
    source
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub path: String,
    pub line: Option<usize>,
    pub text: Option<String>,
}

/// The normalized result collector used by every search backend.
pub struct Page {
    cursor: usize,
    limit: usize,
    total: usize,
    hits: Vec<Hit>,
    skipped: Vec<String>,
}

impl Page {
    pub fn new(cursor: usize, limit: usize) -> Page {
        Page {
            cursor,
            limit,
            total: 0,
            hits: Vec::new(),
            skipped: Vec::new(),
        }
    }

    pub fn push(&mut self, hit: Hit) {
        if self.total >= self.cursor && self.hits.len() < self.limit {
            self.hits.push(hit);
        }
        self.total += 1;
    }

    pub fn skipped(&mut self, notice: String) {
        self.skipped.push(notice);
    }

    pub fn render(self, pattern: &str) -> Result<String, String> {
        if self.cursor > self.total {
            return Err(format!(
                "'cursor' {} exceeds the {} available matches",
                self.cursor, self.total
            ));
        }
        let mut lines: Vec<String> = self
            .hits
            .iter()
            .map(|hit| match (&hit.line, &hit.text) {
                (Some(line), Some(text)) => format!("{}:{line}:{text}", hit.path),
                _ => hit.path.clone(),
            })
            .collect();
        let through = self.cursor + self.hits.len();
        if self.total == 0 {
            lines.push(format!("no matches for '{pattern}'"));
        } else if self.cursor == self.total {
            lines.push(format!(
                "[cursor {} is at end of {} matches]",
                self.cursor, self.total
            ));
        } else if through < self.total {
            lines.push(format!(
                "[next cursor: {through}; showing {}-{through} of {}]",
                self.cursor + 1,
                self.total
            ));
        } else if self.cursor > 0 {
            lines.push(format!(
                "[showing {}-{through} of {}]",
                self.cursor + 1,
                self.total
            ));
        }
        if !self.skipped.is_empty() {
            lines.push(format!(
                "[skipped oversized files: {}]",
                self.skipped.join(", ")
            ));
        }
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_regex_modes_are_distinct() {
        let resources = Resources::default();
        let literal = Matcher::new("a.+z", false, false, resources).unwrap();
        let regex = Matcher::new("a.+z", true, false, resources).unwrap();
        assert!(literal.is_match("literal a.+z text"));
        assert!(!literal.is_match("alphabet soup z"));
        assert!(regex.is_match("alphabet soup z"));
    }

    #[test]
    fn configured_regex_limits_and_case_control_are_enforced() {
        let resources = Resources {
            regex_nest_limit: 2,
            ..Resources::default()
        };
        let error = Matcher::new("((((a))))", true, false, resources)
            .err()
            .expect("nested expression must be refused");
        assert!(error.contains("nested"), "{error}");

        let folded = Matcher::new("δelta", true, true, Resources::default()).unwrap();
        assert!(folded.is_match("ΔELTA"));
        assert!(Matcher::new("[", true, false, Resources::default()).is_err());
    }

    #[test]
    fn multiple_globs_match_paths_and_exclusions_win() {
        let filter = FileFilter::new(
            &["*.rs".to_string(), "docs/**".to_string()],
            &["src/generated/**".to_string()],
            Resources::default(),
        )
        .unwrap();
        assert!(filter.accepts("src/main.rs"));
        assert!(filter.accepts("docs/guide.txt"));
        assert!(!filter.accepts("src/generated/code.rs"));
        assert!(!filter.accepts("notes.txt"));

        let question =
            FileFilter::new(&["src/ma?n.rs".to_string()], &[], Resources::default()).unwrap();
        assert!(question.accepts("src/main.rs"));
        assert!(!question.accepts("src/ma/in.rs"));
        assert!(FileFilter::new(&[String::new()], &[], Resources::default()).is_err());
    }

    #[test]
    fn normalized_pages_have_stable_continuations() {
        let mut page = Page::new(1, 2);
        for number in 1..=4 {
            page.push(Hit {
                path: format!("file-{number}"),
                line: None,
                text: None,
            });
        }
        assert_eq!(
            page.render("file").unwrap(),
            "file-2\nfile-3\n[next cursor: 3; showing 2-3 of 4]"
        );

        let mut beyond = Page::new(5, 2);
        beyond.push(Hit {
            path: "only".to_string(),
            line: None,
            text: None,
        });
        assert!(beyond.render("only").unwrap_err().contains("1 available"));
    }
}
