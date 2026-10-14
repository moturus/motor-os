pub struct Pattern(Vec<Token>);

enum Token {
    Literal(char),
    Any,
    Star,
    Class {
        negate: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Pattern {
    pub fn parse(pattern: &str) -> Result<Self, String> {
        let chars = pattern.chars().collect::<Vec<_>>();
        let mut tokens = Vec::new();
        let mut index = 0;
        while index < chars.len() {
            match chars[index] {
                '*' => tokens.push(Token::Star),
                '?' => tokens.push(Token::Any),
                '[' => {
                    let negate = chars.get(index + 1) == Some(&'!');
                    let start = index + 1 + usize::from(negate);
                    let end = chars
                        .iter()
                        .enumerate()
                        .skip(start + 1)
                        .find(|(_, value)| **value == ']')
                        .map(|(index, _)| index)
                        .ok_or_else(|| format!("invalid character class in pattern `{pattern}`"))?;
                    let mut ranges = Vec::new();
                    let mut position = start;
                    while position < end {
                        if position + 2 < end && chars[position + 1] == '-' {
                            ranges.push((chars[position], chars[position + 2]));
                            position += 3;
                        } else {
                            ranges.push((chars[position], chars[position]));
                            position += 1;
                        }
                    }
                    tokens.push(Token::Class { negate, ranges });
                    index = end;
                }
                character => tokens.push(Token::Literal(character)),
            }
            index += 1;
        }
        Ok(Self(tokens))
    }

    pub fn matches(&self, name: &str) -> bool {
        let chars = name.chars().collect::<Vec<_>>();
        let mut active = vec![false; chars.len() + 1];
        active[0] = true;
        // Each row advances one token. Star closure is linear, avoiding
        // exponential backtracking on adversarial patterns or filenames.
        for token in &self.0 {
            let mut next = vec![false; active.len()];
            for position in 0..active.len() {
                if matches!(token, Token::Star) {
                    next[position] = active[position] || (position > 0 && next[position - 1]);
                } else if position < chars.len() && active[position] {
                    let character = chars[position];
                    let matched = match token {
                        Token::Literal(value) => *value == character,
                        Token::Any => true,
                        Token::Class { negate, ranges } => {
                            ranges
                                .iter()
                                .any(|(start, end)| *start <= character && character <= *end)
                                != *negate
                        }
                        Token::Star => unreachable!(),
                    };
                    next[position + 1] = matched;
                }
            }
            active = next;
        }
        active[chars.len()]
    }
}
