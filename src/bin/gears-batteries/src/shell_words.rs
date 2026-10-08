//! Static shell words for the accident-prevention policy, not confinement.

#[derive(Debug, PartialEq)]
pub enum Token {
    Word(String),
    Separator(char),
}

pub fn tokenize(command: &str) -> Result<Vec<Token>, String> {
    if command.len() > 64 * 1024 {
        return Err("shell policy input exceeds 64 KiB".into());
    }
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut parameter = false;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            } else {
                word.push(ch);
            }
        } else if ch == '\\' {
            let escaped = chars.next().ok_or("unfinished shell escape")?;
            if escaped != '\n' {
                word.push(escaped);
                started = true;
            }
        } else if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                word.push(ch);
            }
        } else if matches!(ch, '\'' | '"') {
            started = true;
            quote = Some(ch);
        } else if ch == '#' && !started {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            tokens.push(Token::Separator('\n'));
        } else if (ch == '{' && word.ends_with('$')) || (ch == '}' && parameter) {
            // `${NAME}` is part of a word, not a brace group.
            parameter = ch == '{';
            word.push(ch);
        } else if ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '(' | ')' | '{' | '}') {
            if started {
                tokens.push(Token::Word(std::mem::take(&mut word)));
                started = false;
            }
            if !ch.is_whitespace() || ch == '\n' {
                tokens.push(Token::Separator(ch));
            }
        } else {
            word.push(ch);
            started = true;
        }
    }
    if quote.is_some() {
        return Err("unfinished shell quote".into());
    }
    if started {
        tokens.push(Token::Word(word));
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_quoted_scripts_and_literal_empty_words() {
        assert_eq!(
            tokenize("cd '/a b'; /bin/sh -c \"rm -rf /user\" && printf ''").unwrap(),
            vec![
                Token::Word("cd".into()),
                Token::Word("/a b".into()),
                Token::Separator(';'),
                Token::Word("/bin/sh".into()),
                Token::Word("-c".into()),
                Token::Word("rm -rf /user".into()),
                Token::Separator('&'),
                Token::Separator('&'),
                Token::Word("printf".into()),
                Token::Word("".into())
            ]
        );
        assert_eq!(
            tokenize("echo 'a\\b' a\\ b # ignore rm /user\nnext").unwrap(),
            vec![
                Token::Word("echo".into()),
                Token::Word("a\\b".into()),
                Token::Word("a b".into()),
                Token::Separator('\n'),
                Token::Word("next".into())
            ]
        );
        assert_eq!(
            tokenize("printf a\\\nb").unwrap(),
            vec![Token::Word("printf".into()), Token::Word("ab".into())]
        );
        assert!(tokenize("sh -c 'unfinished").is_err());
        assert!(tokenize("echo unfinished\\").is_err());
        assert!(tokenize(&"x".repeat(65537)).is_err());
        assert_eq!(
            tokenize("rm ${HOME}/k; { a; }").unwrap(),
            vec![
                Token::Word("rm".into()),
                Token::Word("${HOME}/k".into()),
                Token::Separator(';'),
                Token::Separator('{'),
                Token::Word("a".into()),
                Token::Separator(';'),
                Token::Separator('}')
            ]
        );
    }
}
