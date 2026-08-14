//! Portable search primitives shared by native search and optional accelerators.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use regex::bytes::RegexBuilder;

use crate::config::Resources;

/// One bounded pattern with identical literal and regular-expression modes.
pub struct Matcher(regex::bytes::Regex);

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
        self.is_match_bytes(text.as_bytes())
    }

    pub fn is_match_bytes(&self, bytes: &[u8]) -> bool {
        self.0.is_match(bytes)
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub path: String,
    pub line: Option<usize>,
    pub text: Option<String>,
}

/// The normalized result collector used by every search backend.
#[derive(Clone)]
pub struct Page {
    cursor: usize,
    limit: usize,
    total: usize,
    hits: Vec<Hit>,
    skipped: Vec<String>,
}

pub fn find_rg() -> Option<PathBuf> {
    find_on_path("rg", std::env::var_os("PATH").as_deref())
}

fn find_on_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?).find_map(|directory| {
        let candidate = directory.join(name);
        let metadata = candidate.metadata().ok()?;
        if !metadata.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        Some(candidate)
    })
}

/// Search one bounded batch through ripgrep. Any accelerator incompatibility
/// returns `false`; the caller then runs the same files natively.
#[allow(clippy::too_many_arguments)]
pub fn rg_batch(
    program: &Path,
    root: &Path,
    files: &[PathBuf],
    pattern: &str,
    regular_expression: bool,
    ignore_case: bool,
    resources: Resources,
    page: &mut Page,
    execution: Option<&super::Execution>,
) -> bool {
    let mut args = vec![
        "--json".to_string(),
        "--threads=1".to_string(),
        "--no-config".to_string(),
        "--no-ignore".to_string(),
        "--hidden".to_string(),
        "--no-follow".to_string(),
        "--text".to_string(),
        "--encoding=none".to_string(),
        "--engine=default".to_string(),
        format!("--max-filesize={}", resources.search_max_file_bytes),
        format!("--regex-size-limit={}", resources.regex_size_limit_bytes),
        format!("--dfa-size-limit={}", resources.regex_dfa_size_limit_bytes),
    ];
    if !regular_expression {
        args.push("--fixed-strings".to_string());
    }
    if ignore_case {
        args.push("--ignore-case".to_string());
    }
    args.push("--".to_string());
    args.push(pattern.to_string());
    args.extend(files.iter().map(|file| file.display().to_string()));

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let Ok(mut child) = crate::platform::spawn(&mut command) else {
        return false;
    };
    let Some(stdout) = child.stdout.take() else {
        return false;
    };
    let Some(stderr) = child.stderr.take() else {
        return false;
    };
    let mut known = HashMap::new();
    for file in files {
        let Some(path) = file.to_str() else {
            return false;
        };
        known.insert(
            path.to_string(),
            file.strip_prefix(root)
                .unwrap_or(file)
                .display()
                .to_string(),
        );
    }
    let collected = Arc::new(Mutex::new(page.clone()));
    let into = collected.clone();
    let reader = std::thread::spawn(move || parse_rg(stdout, &known, &into));
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(8192).read_to_end(&mut bytes);
    });
    let started = Instant::now();
    let timeout = super::run::DEFAULT_TIMEOUT;
    let bounded = execution.map(|state| state.with_deadline(started + timeout));
    let end = super::run::wait(&mut child, started, timeout, bounded.as_ref());
    let parsed = reader.join().is_ok_and(|result| result.is_ok());
    let drained = errors.join().is_ok();
    let exited = matches!(
        end,
        Ok(super::run::ProcessEnd::Exited(status)) if matches!(status.code(), Some(0 | 1))
    );
    if !(parsed && drained && exited) {
        return false;
    }
    let Ok(collected) = Arc::try_unwrap(collected) else {
        return false;
    };
    *page = collected.into_inner().unwrap();
    true
}

fn parse_rg(
    stdout: impl Read,
    known: &HashMap<String, String>,
    page: &Arc<Mutex<Page>>,
) -> Result<(), String> {
    for line in BufReader::new(stdout).lines() {
        let value: serde_json::Value =
            serde_json::from_str(&line.map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if value["type"] != "match" {
            continue;
        }
        let path = value["data"]["path"]["text"]
            .as_str()
            .ok_or("ripgrep returned a non-UTF-8 path")?;
        let line = value["data"]["line_number"]
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .ok_or("ripgrep returned an invalid line number")?;
        let text = value["data"]["lines"]["text"]
            .as_str()
            .ok_or("ripgrep returned non-UTF-8 content")?;
        let path = known
            .get(path)
            .ok_or("ripgrep returned a path outside its requested batch")?;
        page.lock().unwrap().push(Hit {
            path: path.clone(),
            line: Some(line),
            text: Some(super::clip(text.trim_end(), 200)),
        });
    }
    Ok(())
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

    #[test]
    fn an_absent_or_non_executable_rg_is_a_normal_miss() {
        let base = std::env::temp_dir().join(format!("gears-rg-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).unwrap();
        std::fs::write(base.join("rg"), "not an executable").unwrap();
        let path = std::env::join_paths([&base]).unwrap();
        #[cfg(unix)]
        assert_eq!(find_on_path("rg", Some(&path)), None);
        assert_eq!(find_on_path("definitely-absent-rg", Some(&path)), None);
        std::fs::remove_dir_all(base).unwrap();
    }
}
