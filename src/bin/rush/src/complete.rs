//! Tab completion.
//!
//! Deliberately a *pure* module: [`complete`] takes the line and the cursor and
//! returns candidates, touching the terminal not at all. That is what lets it be
//! unit-tested (see the tests below) while [`crate::term`] keeps only the
//! rendering.
//!
//! Three kinds of completion, chosen by what the cursor sits on:
//!
//! - **Command** — the first word of a command (`ls; ec<TAB>`, `if tr<TAB>`,
//!   `FOO=1 ec<TAB>`): builtins, functions, aliases, and the executables on
//!   `$PATH`.
//! - **Variable** — a `$NAME` tail (`echo $HO<TAB>`): the shell's variables.
//! - **Pathname** — everything else, and any word containing a `/`.
//!
//! # Quoting
//!
//! Completion has to run the word through quote removal (`ls 'my fi<TAB>` is
//! looking for `my fi…`, not `'my fi…`) and then put the quotes back on the way
//! in, or the completed name would not survive the expansion it is about to be
//! fed to. So the scan below tracks quoting as the lexer does, reports the
//! quoting context at the cursor, and [`quote_for_insert`] re-quotes each
//! candidate for that context.

use std::path::Path;

use crate::builtins;
use crate::shell::Shell;

/// The quoting context the cursor sits in, which decides how a completion has to
/// be escaped on the way back into the line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Quote {
    None,
    Single,
    Double,
}

/// What completing at the cursor produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Completion {
    /// Char index in the line where the text being replaced starts.
    pub start: usize,
    /// The candidates, as *literal* (unquoted) text: sorted, deduplicated, and
    /// each a full replacement for `line[start..cursor]`. A directory ends in
    /// `/`, which is also how the editor knows not to append a space.
    pub candidates: Vec<String>,
    /// The quoting in effect at `start`.
    pub quote: Quote,
}

/// The result of reading the line up to the cursor: what the shell would make of
/// the word being typed.
struct Scan {
    /// Char index in the line where the current word starts.
    start: usize,
    /// The current word with quotes removed — what a filename must match.
    literal: String,
    /// For each char of `literal`, its char index in the line. Completion of a
    /// `$NAME` tail needs to map back from the literal to the line.
    map: Vec<usize>,
    /// For each char of `literal`, whether quoting stripped its special
    /// meaning — single-quoted, or backslash-escaped. A `$` inside *double*
    /// quotes is not escaped: it still introduces a parameter, which is why
    /// this is not simply "was inside quotes".
    escaped: Vec<bool>,
    /// The quoting in effect at the cursor.
    quote: Quote,
    /// Whether the current word is the first of its command.
    command_position: bool,
}

/// A word being accumulated by [`scan`]: its literal text, and per-literal-char
/// the line index it came from and whether quoting stripped its meaning.
type WordAcc = (String, Vec<usize>, Vec<bool>);

fn begin(word: &mut Option<WordAcc>) -> &mut WordAcc {
    word.get_or_insert_with(|| (String::new(), Vec::new(), Vec::new()))
}

/// Add one literal char, which the line spells at index `at`.
fn push(word: &mut Option<WordAcc>, at: usize, c: char, escaped: bool) {
    let w = begin(word);
    w.0.push(c);
    w.1.push(at);
    w.2.push(escaped);
}

/// Read `line[..cursor]` the way the lexer would, to find the word under the
/// cursor, its literal text, and whether it stands in command position.
fn scan(line: &[char], cursor: usize) -> Scan {
    let mut quote = Quote::None;
    let mut word: Option<WordAcc> = None;
    // Words already finished in this command, needed only to tell an assignment
    // prefix (`FOO=1 cmd`) from a real command word.
    let mut prior: Vec<String> = Vec::new();

    let mut i = 0;
    while i < cursor {
        let c = line[i];
        match quote {
            Quote::Single => {
                if c == '\'' {
                    quote = Quote::None;
                } else {
                    push(&mut word, i, c, true);
                }
                i += 1;
            }
            Quote::Double => {
                // Inside double quotes a backslash escapes only these four…
                if c == '\\' && i + 1 < cursor && matches!(line[i + 1], '"' | '\\' | '$' | '`') {
                    push(&mut word, i, line[i + 1], true);
                    i += 2;
                } else if c == '"' {
                    quote = Quote::None;
                    i += 1;
                } else {
                    // …so everything else keeps its meaning, `$` included:
                    // `"$HO<TAB>` is completing a variable, not a filename.
                    push(&mut word, i, c, false);
                    i += 1;
                }
            }
            Quote::None => match c {
                '\\' if i + 1 < cursor => {
                    // A backslash-newline is a line continuation: it vanishes.
                    if line[i + 1] != '\n' {
                        push(&mut word, i, line[i + 1], true);
                    }
                    i += 2;
                }
                '\'' => {
                    // An empty quoted word still starts a word: `''<TAB>`.
                    begin(&mut word);
                    quote = Quote::Single;
                    i += 1;
                }
                '"' => {
                    begin(&mut word);
                    quote = Quote::Double;
                    i += 1;
                }
                ' ' | '\t' => {
                    if let Some(w) = word.take() {
                        prior.push(w.0);
                    }
                    i += 1;
                }
                // Unquoted operators: they end a word, and every one of these
                // also begins a new command.
                ';' | '&' | '|' | '(' | ')' | '\n' | '`' => {
                    word.take();
                    prior.clear();
                    i += 1;
                }
                '<' | '>' => {
                    // A redirection ends the word; what follows is a filename,
                    // not a command, and is not part of the command's words.
                    word.take();
                    i += 1;
                }
                c => {
                    push(&mut word, i, c, false);
                    i += 1;
                }
            },
        }
    }

    let (literal, map, escaped) = word.unwrap_or_default();
    // Where a completion is inserted: at the first *literal* character, not at
    // the quote in front of it — `ls 'my fi<TAB>` must keep its opening quote,
    // since the re-quoting only escapes the candidate, it does not reopen it.
    // With no literal characters yet (`ls '<TAB>`), that is the cursor itself.
    let start = map.first().copied().unwrap_or(cursor);
    // A word is in command position when nothing but assignments precedes it —
    // `FOO=1 cmd` — or when the word before it is one that introduces a command.
    let command_position = prior
        .iter()
        .all(|w| is_assignment(w) || introduces_command(w));
    Scan {
        start,
        literal,
        map,
        escaped,
        quote,
        command_position,
    }
}

/// `NAME=…`: an assignment prefix, which does not make the word after it an
/// argument.
fn is_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => crate::is_valid_var_name(name),
        None => false,
    }
}

/// Reserved words after which the next word is a command name, so `if tr<TAB>`
/// and `while sl<TAB>` complete commands rather than files.
fn introduces_command(word: &str) -> bool {
    matches!(
        word,
        "if" | "then" | "else" | "elif" | "while" | "until" | "do" | "!" | "{"
    )
}

/// Complete the word under the cursor. `cursor` is a char index into `line`.
pub fn complete(line: &[char], cursor: usize, shell: &Shell) -> Completion {
    let scan = scan(line, cursor);

    // `$NAME` under the cursor: complete a variable, replacing only the `$NAME`
    // tail rather than the whole word (`ls $HOM<TAB>` → `ls $HOME`).
    if let Some(c) = complete_variable(&scan, shell) {
        return c;
    }

    let candidates = if scan.command_position && !scan.literal.contains('/') {
        complete_command(&scan.literal, shell)
    } else {
        complete_path(&scan.literal, shell)
    };
    Completion {
        start: scan.start,
        candidates,
        quote: scan.quote,
    }
}

/// A `$NAME` tail under the cursor, if there is one: the last unquoted `$` in
/// the word, followed only by name characters.
fn complete_variable(scan: &Scan, shell: &Shell) -> Option<Completion> {
    let chars: Vec<char> = scan.literal.chars().collect();
    let dollar = (0..chars.len())
        .rev()
        .find(|&i| chars[i] == '$' && !scan.escaped[i])?;
    let name = &chars[dollar + 1..];
    // `$` alone completes every variable; otherwise the tail must be a name (a
    // `${`, a `$(`, or `$1` is something else, and is left alone).
    if !name.is_empty() {
        let first = name[0];
        if !(first.is_ascii_alphabetic() || first == '_') {
            return None;
        }
        if !name[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == '_') {
            return None;
        }
    }
    let prefix: String = name.iter().collect();
    let mut candidates: Vec<String> = shell
        .vars_sorted()
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| n.starts_with(&prefix))
        .collect();
    candidates.sort();
    candidates.dedup();
    Some(Completion {
        // The `$` stays put and only the name is replaced. Were the `$` part of
        // the candidate, re-quoting would escape it (`\$HOME`) and turn the
        // expansion the user is completing into a literal.
        //
        // The name's own first character says where it starts, rather than "one
        // past the `$`": the two are not always adjacent in the *line*, since
        // quoting sits between them in `echo "$"HO<TAB>` — and replacing from
        // one-past-the-`$` there would swallow the closing quote. With no name
        // yet (`echo $<TAB>`), one past the `$` is right, and is the cursor.
        start: scan
            .map
            .get(dollar + 1)
            .copied()
            .unwrap_or(scan.map[dollar] + 1),
        candidates,
        quote: scan.quote,
    })
}

/// Command names starting with `prefix`: builtins, functions, aliases, and every
/// executable on `$PATH`.
fn complete_command(prefix: &str, shell: &Shell) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut take = |name: &str| {
        if name.starts_with(prefix) {
            out.push(name.to_string());
        }
    };
    for name in builtins::names() {
        take(name);
    }
    for name in shell.function_names() {
        take(&name);
    }
    for (name, _) in shell.aliases_sorted() {
        take(&name);
    }
    if let Some(path) = shell.get("PATH") {
        for dir in path.split(':') {
            // An empty `$PATH` entry means the current directory (POSIX §8.3).
            let dir = if dir.is_empty() { "." } else { dir };
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with(prefix) {
                    continue;
                }
                if builtins::is_executable_file(&entry.path()) {
                    out.push(name);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Filenames matching `prefix`, each returned as a full replacement for it
/// (`src/ma` → `src/main.rs`), with a `/` appended to directories.
fn complete_path(prefix: &str, shell: &Shell) -> Vec<String> {
    // Split into the directory to read and the name to match within it.
    let (dir_text, file_part) = match prefix.rfind('/') {
        Some(i) => (&prefix[..=i], &prefix[i + 1..]),
        None => ("", prefix),
    };
    // `~/…` names $HOME. `~user` is not supported (no user database on Motor
    // OS — a documented limit), so it is left alone rather than guessed at.
    let dir_path = if dir_text.starts_with("~/") {
        match shell.get("HOME") {
            Some(home) => format!("{}{}", home, &dir_text[1..]),
            None => return Vec::new(),
        }
    } else if dir_text.is_empty() {
        ".".to_string()
    } else {
        dir_text.to_string()
    };

    let Ok(entries) = std::fs::read_dir(&dir_path) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(file_part) {
            continue;
        }
        // The leading-dot rule, as in globbing: a dotfile shows up only when the
        // prefix asks for one.
        if name.starts_with('.') && !file_part.starts_with('.') {
            continue;
        }
        let is_dir = entry
            .file_type()
            .map(|t| {
                t.is_dir() || (t.is_symlink() && Path::new(&dir_path).join(&name).is_dir())
            })
            .unwrap_or(false);
        let suffix = if is_dir { "/" } else { "" };
        out.push(format!("{dir_text}{name}{suffix}"));
    }
    out.sort();
    out.dedup();
    out
}

/// The longest prefix every candidate shares — what a Tab inserts when the
/// completion is ambiguous.
pub fn common_prefix(candidates: &[String]) -> String {
    let Some(first) = candidates.first() else {
        return String::new();
    };
    let mut len = first.chars().count();
    for c in &candidates[1..] {
        len = len.min(
            first
                .chars()
                .zip(c.chars())
                .take_while(|(a, b)| a == b)
                .count(),
        );
    }
    first.chars().take(len).collect()
}

/// Re-quote a literal candidate so that inserting it into a `quote` context
/// yields that literal back after expansion.
pub fn quote_for_insert(literal: &str, quote: Quote) -> String {
    let mut out = String::with_capacity(literal.len());
    match quote {
        // Inside '…' nothing is special but the closing quote itself, which has
        // to leave and re-enter the quoting: the classic `'\''`.
        Quote::Single => {
            for c in literal.chars() {
                if c == '\'' {
                    out.push_str("'\\''");
                } else {
                    out.push(c);
                }
            }
        }
        // Inside "…" a backslash escapes only these four; everything else,
        // including a space, is already literal.
        Quote::Double => {
            for c in literal.chars() {
                if matches!(c, '"' | '\\' | '$' | '`') {
                    out.push('\\');
                }
                out.push(c);
            }
        }
        Quote::None => {
            for (i, c) in literal.chars().enumerate() {
                if needs_escape(c) || (i == 0 && matches!(c, '~' | '#')) {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out
}

/// Characters that must be escaped to survive as themselves in an unquoted word.
fn needs_escape(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t'
            | '\n'
            | '"'
            | '\''
            | '\\'
            | '$'
            | '`'
            | '&'
            | ';'
            | '|'
            | '<'
            | '>'
            | '('
            | ')'
            | '*'
            | '?'
            | '['
            | ']'
            | '!'
            | '{'
            | '}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    /// Scan `s`, whose cursor is at the end.
    fn scan_end(s: &str) -> Scan {
        let c = chars(s);
        let n = c.len();
        scan(&c, n)
    }

    #[test]
    fn scan_finds_the_word_under_the_cursor() {
        let s = scan_end("echo hel");
        assert_eq!(s.start, 5);
        assert_eq!(s.literal, "hel");
        assert!(!s.command_position);
    }

    #[test]
    fn the_first_word_is_a_command() {
        assert!(scan_end("ec").command_position);
        assert!(scan_end("  ec").command_position);
        assert!(scan_end("").command_position);
    }

    #[test]
    fn an_operator_starts_a_new_command() {
        for line in ["ls; ec", "ls | ec", "ls && ec", "ls || ec", "(ec", "ls & ec"] {
            assert!(scan_end(line).command_position, "in {line:?}");
        }
    }

    #[test]
    fn a_reserved_word_introduces_a_command() {
        for line in ["if tr", "while tr", "until tr", "do tr", "then tr", "! tr"] {
            assert!(scan_end(line).command_position, "in {line:?}");
        }
    }

    #[test]
    fn an_assignment_prefix_still_leaves_a_command() {
        assert!(scan_end("FOO=bar ec").command_position);
        assert!(scan_end("FOO=bar BAZ=1 ec").command_position);
        // But an argument does not.
        assert!(!scan_end("echo FOO=bar ec").command_position);
    }

    #[test]
    fn a_redirection_target_is_a_filename_not_a_command() {
        let s = scan_end("ls > /tm");
        assert!(!s.command_position);
        assert_eq!(s.literal, "/tm");
    }

    #[test]
    fn quotes_are_removed_from_the_word_and_reported() {
        let s = scan_end("ls 'my fi");
        assert_eq!(s.literal, "my fi");
        assert_eq!(s.quote, Quote::Single);
        // Inside the quote, not at it: the completion replaces the text, and
        // must not swallow the `'` that is holding it together.
        assert_eq!(s.start, 4);

        let s = scan_end("ls \"my fi");
        assert_eq!(s.literal, "my fi");
        assert_eq!(s.quote, Quote::Double);

        let s = scan_end(r"ls my\ fi");
        assert_eq!(s.literal, "my fi");
        assert_eq!(s.quote, Quote::None);
        assert_eq!(s.start, 3);
    }

    #[test]
    fn a_closed_quote_leaves_no_quoting_in_effect() {
        let s = scan_end("ls 'my file' ne");
        assert_eq!(s.quote, Quote::None);
        assert_eq!(s.literal, "ne");
    }

    #[test]
    fn the_literal_maps_back_to_line_positions() {
        //             0123456789
        let s = scan_end(r"ls a\ b$H");
        assert_eq!(s.literal, "a b$H");
        // The `$` is at line index 7.
        assert_eq!(s.map[3], 7);
        assert!(s.escaped[1], "the escaped space is quoted");
        assert!(!s.escaped[3], "the dollar is not");
    }

    #[test]
    fn common_prefix_is_the_longest_shared_one() {
        let c = |v: &[&str]| common_prefix(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(c(&["foobar", "foobaz"]), "fooba");
        assert_eq!(c(&["foo"]), "foo");
        assert_eq!(c(&["foo", "bar"]), "");
        assert_eq!(c(&[]), "");
        // Char-wise, not byte-wise: these share no character at all.
        assert_eq!(c(&["é", "e"]), "");
    }

    #[test]
    fn insertion_escapes_for_the_quoting_in_effect() {
        assert_eq!(quote_for_insert("my file", Quote::None), r"my\ file");
        assert_eq!(quote_for_insert("my file", Quote::Double), "my file");
        assert_eq!(quote_for_insert("my file", Quote::Single), "my file");
        assert_eq!(quote_for_insert(r"a$b", Quote::Double), r"a\$b");
        assert_eq!(quote_for_insert(r"a$b", Quote::Single), r"a$b");
        assert_eq!(quote_for_insert("it's", Quote::Single), r"it'\''s");
        // A leading `~`/`#` is only special at the start of a word.
        assert_eq!(quote_for_insert("~x", Quote::None), r"\~x");
        assert_eq!(quote_for_insert("a~x", Quote::None), "a~x");
        // A directory's trailing slash is not escaped.
        assert_eq!(quote_for_insert("src/", Quote::None), "src/");
    }

    /// A scratch directory of files to complete against.
    struct Fixture {
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("rush-comp-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("subdir")).unwrap();
            std::fs::write(dir.join("alpha.txt"), "").unwrap();
            std::fs::write(dir.join("alpine.txt"), "").unwrap();
            std::fs::write(dir.join("beta.txt"), "").unwrap();
            std::fs::write(dir.join(".hidden"), "").unwrap();
            std::fs::write(dir.join("with space.txt"), "").unwrap();
            Self { dir }
        }
        fn path(&self, rel: &str) -> String {
            format!("{}/{rel}", self.dir.display())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn complete_str(line: &str, shell: &Shell) -> Vec<String> {
        let c = chars(line);
        let n = c.len();
        complete(&c, n, shell).candidates
    }

    #[test]
    fn path_completion_finds_matches_and_marks_directories() {
        let f = Fixture::new("paths");
        let sh = Shell::new();
        let got = complete_str(&format!("ls {}", f.path("al")), &sh);
        assert_eq!(got, [f.path("alpha.txt"), f.path("alpine.txt")]);

        let got = complete_str(&format!("ls {}", f.path("sub")), &sh);
        assert_eq!(got, [f.path("subdir/")], "a directory ends with a slash");
    }

    #[test]
    fn path_completion_hides_dotfiles_unless_asked() {
        let f = Fixture::new("dots");
        let sh = Shell::new();
        let all = complete_str(&format!("ls {}", f.path("")), &sh);
        assert!(!all.iter().any(|c| c.ends_with(".hidden")));
        let dots = complete_str(&format!("ls {}", f.path(".")), &sh);
        assert_eq!(dots, [f.path(".hidden")]);
    }

    #[test]
    fn path_completion_matches_a_quoted_word_by_its_literal_text() {
        let f = Fixture::new("quoted");
        let sh = Shell::new();
        // The typed text has a quote in it; the file does not.
        let line = format!("ls '{}", f.path("with sp"));
        let c = chars(&line);
        let n = c.len();
        let got = complete(&c, n, &sh);
        assert_eq!(got.candidates, [f.path("with space.txt")]);
        assert_eq!(got.quote, Quote::Single);
        // The candidate is replaced from just after the opening quote.
        assert_eq!(got.start, 4);
    }

    #[test]
    fn an_unreadable_directory_completes_to_nothing_rather_than_failing() {
        let sh = Shell::new();
        assert!(complete_str("ls /nonexistent-dir-xyz/f", &sh).is_empty());
    }

    #[test]
    fn command_completion_offers_builtins_and_path_executables() {
        let f = Fixture::new("cmds");
        let mut sh = Shell::new();
        // A file with the executable bit, and one without.
        let bin = f.dir.join("rush-test-cmd");
        std::fs::write(&bin, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        sh.set("PATH", f.dir.display().to_string()).unwrap();

        let got = complete_str("rush-test-c", &sh);
        assert_eq!(got, ["rush-test-cmd"]);

        // Builtins are commands too.
        assert!(complete_str("expo", &sh).contains(&"export".to_string()));
        // …but only in command position.
        assert!(!complete_str("ls expo", &sh).contains(&"export".to_string()));
    }

    #[test]
    fn command_completion_offers_functions_and_aliases() {
        let mut sh = Shell::new();
        sh.set_alias("myalias", "ls -l".to_string());
        let body = std::rc::Rc::new(crate::ast::FunctionBody {
            body: crate::ast::CompoundCommand::Brace(crate::ast::List(vec![])),
            redirects: vec![],
        });
        sh.define_function("myfunc", body);
        assert_eq!(complete_str("myali", &sh), ["myalias"]);
        assert_eq!(complete_str("myfun", &sh), ["myfunc"]);
    }

    #[test]
    fn a_command_word_with_a_slash_completes_as_a_path() {
        let f = Fixture::new("cmdpath");
        let sh = Shell::new();
        // In command position, but it names a path: `./al<TAB>`.
        let got = complete_str(&f.path("al"), &sh);
        assert_eq!(got, [f.path("alpha.txt"), f.path("alpine.txt")]);
    }

    #[test]
    fn variable_completion_replaces_only_the_dollar_name() {
        let mut sh = Shell::new();
        sh.set("RUSH_TEST_VAR", "1".to_string()).unwrap();
        let line = chars("echo $RUSH_TEST_V");
        let n = line.len();
        let got = complete(&line, n, &sh);
        // The name only: the `$` is not part of the candidate, or re-quoting
        // would escape it into a literal.
        assert_eq!(got.candidates, ["RUSH_TEST_VAR"]);
        assert_eq!(got.start, 6, "replacement starts just after the `$`");

        // Inside double quotes a `$` is still a parameter.
        let line = chars("echo \"$RUSH_TEST_V");
        let n = line.len();
        assert_eq!(complete(&line, n, &sh).candidates, ["RUSH_TEST_VAR"]);
    }

    #[test]
    fn variable_completion_starts_at_the_name_not_past_the_dollar() {
        let mut sh = Shell::new();
        sh.set("RUSH_TEST_VAR", "1".to_string()).unwrap();
        // A quote between the `$` and the name: replacing from one-past-the-`$`
        // would eat the `"` and change what the line means.
        //         0123456789
        let line = chars("echo \"$\"RUSH_TEST_V");
        let n = line.len();
        let got = complete(&line, n, &sh);
        assert_eq!(got.candidates, ["RUSH_TEST_VAR"]);
        assert_eq!(got.start, 8, "the R of RUSH_TEST_V, not the closing quote");

        // And with no name at all, it is the cursor.
        let line = chars("echo $");
        let n = line.len();
        assert_eq!(complete(&line, n, &sh).start, 6);
    }

    #[test]
    fn a_quoted_dollar_is_not_a_variable() {
        let mut sh = Shell::new();
        sh.set("RUSH_TEST_VAR", "1".to_string()).unwrap();
        // Inside single quotes, `$` is literal: this is a filename.
        let line = chars("echo '$RUSH_TEST_V");
        let n = line.len();
        let got = complete(&line, n, &sh);
        assert!(!got.candidates.iter().any(|c| c.starts_with('$')));
    }

    #[test]
    fn a_dollar_that_is_not_a_name_is_left_alone() {
        let sh = Shell::new();
        // `${`, `$(` and `$1` are other expansions, not a variable name.
        for line in ["echo ${HOM", "echo $(l", "echo $1"] {
            let c = chars(line);
            let n = c.len();
            let got = complete(&c, n, &sh);
            // Variable completion would replace from just after a `$`; these
            // fall through to pathname completion instead.
            assert!(
                got.start != 6 || got.candidates.is_empty(),
                "{line:?} should not offer variables, got {:?}",
                got.candidates
            );
        }
    }

    #[test]
    fn completing_an_empty_word_starts_at_the_cursor() {
        let f = Fixture::new("empty");
        let sh = Shell::new();
        let line = chars(&format!("ls {}", f.path("")));
        let n = line.len();
        let got = complete(&line, n, &sh);
        assert_eq!(got.start, 3);
        assert!(got.candidates.len() >= 4);
    }
}

