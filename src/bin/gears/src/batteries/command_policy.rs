//! A short static destructive list. Tools still run with the user's authority.

use std::path::{Path, PathBuf};

use crate::hooks::Decision;

use crate::batteries::shell_words::{Token, tokenize};

pub fn inspect(command: &str, cwd: &Path, state: &Path) -> Result<Decision, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    inspect_at(command, cwd.to_path_buf(), state, home.as_deref(), 0)
}

fn inspect_at(
    command: &str,
    mut cwd: PathBuf,
    state: &Path,
    home: Option<&Path>,
    depth: usize,
) -> Result<Decision, String> {
    if depth > 8 {
        return Err("shell policy nesting exceeds eight wrappers".into());
    }
    let tokens = tokenize(command)?;
    if fork_bomb(&tokens) {
        return Ok(Decision::Deny);
    }
    let mut decision = Decision::Ask;
    for group in tokens.split(|token| matches!(token, Token::Separator(_))) {
        let mut words: Vec<&str> = group
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some(word.as_str()),
                _ => None,
            })
            .collect();
        // Keywords and assignments can precede the command on the same line.
        while words.first().is_some_and(|word| {
            assignment(word)
                || matches!(
                    *word,
                    "if" | "then" | "elif" | "else" | "while" | "until" | "do" | "!" | "time"
                )
        }) {
            words.remove(0);
        }
        if words.is_empty() {
            continue;
        }
        while words
            .first()
            .is_some_and(|word| matches!(program(word), "command" | "exec" | "env"))
        {
            words.remove(0);
            while words
                .first()
                .is_some_and(|word| word.starts_with('-') || assignment(word))
            {
                words.remove(0);
            }
        }
        if words.first().is_some_and(|word| program(word) == "sysbox") {
            words.remove(0);
        }
        let Some(first) = words.first() else {
            continue;
        };
        match program(first) {
            "cd" => {
                if let Some(path) = words.iter().skip(1).find(|word| !word.starts_with('-')) {
                    cwd = absolute(&cwd, home, path);
                }
            }
            "sh" | "rush" | "bash" | "dash" => {
                if let Some(at) = words.iter().position(|word| {
                    word.starts_with('-') && !word.starts_with("--") && word[1..].contains('c')
                }) {
                    let script = words.get(at + 1).ok_or("shell -c has no script")?;
                    let nested = inspect_at(script, cwd.clone(), state, home, depth + 1)?;
                    if nested == Decision::Deny {
                        return Ok(nested);
                    }
                    if nested == Decision::Confirm {
                        decision = nested;
                    }
                }
            }
            "rm" if forbidden_rm(&words[1..], &cwd, state, home) => return Ok(Decision::Deny),
            "gix" | "git"
                if matches!(
                    git_command(&words[1..]),
                    Some("push" | "checkout" | "restore")
                ) =>
            {
                decision = Decision::Confirm;
            }
            _ => {}
        }
    }
    Ok(decision)
}

fn git_command<'a>(words: &[&'a str]) -> Option<&'a str> {
    let mut words = words.iter();
    while let Some(word) = words.next() {
        if matches!(*word, "-C" | "-c" | "--git-dir" | "--work-tree") {
            words.next();
        } else if !word.starts_with('-') {
            return Some(word);
        }
    }
    None
}

fn program(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(word)
}

fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.as_bytes()[0].is_ascii_digit()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn absolute(cwd: &Path, home: Option<&Path>, input: &str) -> PathBuf {
    let rest = ["~", "$HOME", "${HOME}"].iter().find_map(|prefix| {
        input
            .strip_prefix(prefix)
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))
    });
    if let (Some(home), Some(rest)) = (home, rest) {
        return absolute(cwd, None, &format!("{}{rest}", home.display()));
    }
    let path = cwd.join(input);
    crate::batteries::paths::normalize(&path).unwrap_or(path)
}

fn forbidden_rm(arguments: &[&str], cwd: &Path, state: &Path, home: Option<&Path>) -> bool {
    let mut options = true;
    let mut recursive = false;
    let mut paths = Vec::new();
    for argument in arguments {
        if options && *argument == "--" {
            options = false;
        } else if options && argument.starts_with('-') {
            recursive |= *argument == "--recursive"
                || (!argument.starts_with("--") && argument.contains(['r', 'R']));
        } else {
            let path = absolute(cwd, home, argument);
            // The Gears directory is compared by its real location.
            paths.push(crate::batteries::paths::resolve_links(&path).unwrap_or(path));
        }
    }
    paths.iter().any(|path| {
        if path.starts_with("/user/cfg") || path.starts_with(state) {
            return true;
        }
        let text = path.to_string_lossy();
        let glob = text.find(['*', '?', '[']);
        let prefix = &text[..glob.unwrap_or(text.len())];
        let contains_cfg = glob.is_some()
            && ("/user/cfg".starts_with(prefix) || state.to_string_lossy().starts_with(prefix));
        contains_cfg
            || recursive
                && ["/", "/system", "/user", "/user/cfg", "/devtools"]
                    .iter()
                    .any(|root| {
                        if glob.is_some() {
                            root.starts_with(prefix)
                        } else {
                            path == Path::new(root)
                        }
                    })
    })
}

fn fork_bomb(tokens: &[Token]) -> bool {
    tokens.windows(4).enumerate().any(|(start, window)| {
        let [
            Token::Word(name),
            Token::Separator('('),
            Token::Separator(')'),
            Token::Separator('{'),
        ] = window
        else {
            return false;
        };
        let body: Vec<_> = tokens[start + 4..]
            .iter()
            .take_while(|token| **token != Token::Separator('}'))
            .collect();
        body.iter()
            .filter(|token| matches!(token, Token::Word(word) if word == name))
            .count()
            >= 2
            && body.contains(&&Token::Separator('|'))
            && body.contains(&&Token::Separator('&'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_protected_deletions_through_wrappers_full_paths_and_cd() {
        for command in [
            "rm -rf /",
            "rm -r /system",
            "/system/bin/sysbox rm -R /devtools",
            "rm /user/cfg/key",
            "cd /user; rm -rf cfg",
            "cd /; /bin/rm --recursive system",
            "sh -c 'rush -c \"rm -rf /user\"'",
            "bash -lc 'cd /user/cfg; rm key'",
            "env MODE=x /bin/rm -rf /system",
            "command rm -rf /user",
            "rm -r /u*",
            "rm /user/cfg/*",
            "rm /home/user/.gears/key",
            ":(){ :|:& };:",
            "f() { f | f & }; f",
        ] {
            assert_eq!(
                inspect(
                    command,
                    Path::new("/workspace"),
                    Path::new("/home/user/.gears")
                )
                .unwrap(),
                Decision::Deny,
                "{command}"
            );
        }
        for command in [
            "rm -rf build",
            "rm /user/tmp/file",
            "printf 'rm -rf /'",
            "echo ':(){:|:&};:'",
            "rm -- ./-rf",
            "gix log restore",
            "bash --rcfile config -c 'printf harmless'",
        ] {
            assert_eq!(
                inspect(
                    command,
                    Path::new("/workspace"),
                    Path::new("/home/user/.gears")
                )
                .unwrap(),
                Decision::Ask,
                "{command}"
            );
        }
        assert_eq!(
            inspect(
                "rm key",
                Path::new("/user/cfg"),
                Path::new("/home/user/.gears")
            )
            .unwrap(),
            Decision::Deny
        );
        assert_eq!(
            inspect(
                "sh -c '/devtools/bin/gix push'",
                Path::new("/workspace"),
                Path::new("/state")
            )
            .unwrap(),
            Decision::Confirm
        );
        assert_eq!(
            inspect(
                "gix -C /workspace restore source",
                Path::new("/workspace"),
                Path::new("/state")
            )
            .unwrap(),
            Decision::Confirm
        );
    }

    #[test]
    fn refuses_deletions_after_shell_keywords_and_through_the_home_directory() {
        let check = |command: &str| {
            inspect_at(
                command,
                PathBuf::from("/workspace"),
                Path::new("/home/user/.gears"),
                Some(Path::new("/home/user")),
                0,
            )
            .unwrap()
        };
        for command in [
            "if [ -d /user/cfg ]; then rm -rf /user/cfg; fi",
            "for d in x; do rm -rf /user; done",
            "while true; do rm /user/cfg/key; done",
            "! rm /user/cfg/key",
            "time rm -rf /",
            "rm -rf ~/.gears",
            "rm -rf \"$HOME/.gears\"",
            "rm ${HOME}/.gears/key",
            "cd ~; rm -rf .gears",
        ] {
            assert_eq!(check(command), Decision::Deny, "{command}");
        }
        for command in [
            "rm -rf ~/build",
            "rm ~other/.gears/key",
            "rm -rf $HOMEDIR/.gears",
        ] {
            assert_eq!(check(command), Decision::Ask, "{command}");
        }
    }
}
