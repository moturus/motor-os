#[derive(PartialEq, Eq, Debug, Default)]
enum State {
    #[default]
    Normal,
    Quoted(char),
    Escape, // Last char was '\'
    QuotedEscape(char),
}

#[derive(Default)]
pub struct LineParser {
    result: Vec<Vec<String>>,
    current_command: Vec<String>,
    current_token: String,

    state: State,
}

impl LineParser {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn process_char(&mut self, c: char) {
        match self.state {
            State::Normal => {
                if c.is_whitespace() {
                    self.finish_token();
                } else if c == '|' {
                    self.finish_command();
                } else if c == '\'' || c == '\"' {
                    self.state = State::Quoted(c);
                } else if c == '\\' {
                    self.state = State::Escape;
                } else {
                    self.current_token.push(c);
                }
            }
            State::Quoted(q) => {
                if c == q {
                    // Consume the quote.
                    self.state = State::Normal;
                } else if c == '\\' {
                    self.state = State::QuotedEscape(q);
                } else if c == '*' {
                    self.current_token.push('*');
                } else {
                    self.current_token.push(c);
                }
            }
            State::Escape => {
                self.current_token.push(c);
                self.state = State::Normal;
            }
            State::QuotedEscape(q) => {
                self.current_token.push(c);
                self.state = State::Quoted(q);
            }
        }
    }

    fn finish_token(&mut self) {
        let token = std::mem::take(&mut self.current_token);
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return;
        }

        if self.current_command.is_empty() {
            self.current_command.push(trimmed.to_owned());
        } else {
            let mut processed = Self::process_arg(trimmed);
            self.current_command.append(&mut processed);
        }
    }

    fn finish_command(&mut self) {
        assert_eq!(self.state, State::Normal);

        self.finish_token();

        if !self.current_command.is_empty() {
            self.result.push(std::mem::take(&mut self.current_command));
        }
    }

    fn process_arg(arg: &str) -> Vec<String> {
        // Disable glob processing: it removes trailing slashes, which
        // are meaningful in commands like mv.
        /*
        let mut result: Vec<String> = Vec::new();

        match glob::glob(arg) {
            Ok(paths) => {
                for entry in paths {
                    match entry {
                        Ok(path) => match path.to_str() {
                            Some(s) => result.push(s.to_owned()),
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        if result.is_empty() {
            result.push(arg.to_owned());
        }

        result.push(arg.to_owned());

        result
        */
        vec![arg.to_owned()]
    }

    // Parse a line; return a vector of pipelined commands to run, each
    // command represented by a vector of strings, with wildcards resolved.
    pub fn parse_line(&mut self, line: &str) -> Option<Vec<Vec<String>>> {
        for c in line.chars() {
            self.process_char(c);
        }

        match self.state {
            State::Normal => {
                self.finish_command();
                if self.result.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.result))
                }
            }
            _ => None,
        }
    }
}
