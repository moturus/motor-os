#[derive(PartialEq, Eq, Debug, Default)]
enum State {
    #[default]
    Normal,
    Quoted(char),
    Escape, // Last char was '\'
    QuotedEscape(char),
    PendingAmpersand, // Saw one '&', waiting to see if next is '&' too.
}

#[derive(Default)]
pub struct LineParser {
    /// Finished pipelines (&&-separated groups), each pipeline is a Vec of commands.
    pipelines: Vec<Vec<Vec<String>>>,
    /// Commands accumulated for the current pipeline.
    current_pipeline: Vec<Vec<String>>,
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
                if c == '&' {
                    self.state = State::PendingAmpersand;
                } else if c.is_whitespace() {
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
            State::PendingAmpersand => {
                if c == '&' {
                    // We saw "&&" — finish the current pipeline.
                    self.finish_pipeline();
                    self.state = State::Normal;
                } else {
                    // A lone '&' — just treat it as a literal character
                    // (background execution is not supported).
                    self.current_token.push('&');
                    self.state = State::Normal;
                    // Re-process the current character in Normal state.
                    self.process_char(c);
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
        self.finish_token();

        if !self.current_command.is_empty() {
            self.current_pipeline
                .push(std::mem::take(&mut self.current_command));
        }
    }

    fn finish_pipeline(&mut self) {
        self.finish_command();

        if !self.current_pipeline.is_empty() {
            self.pipelines
                .push(std::mem::take(&mut self.current_pipeline));
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

    /// Returns true when the parser is waiting for a continuation line
    /// (i.e. the previous line ended with a backslash or an open quote).
    pub fn is_continuation(&self) -> bool {
        !matches!(self.state, State::Normal | State::PendingAmpersand)
    }

    // Parse a line; return a list of &&-separated pipelines.
    // Each pipeline is a vector of piped commands; each command is a
    // vector of strings (argv), with wildcards resolved.
    pub fn parse_line(&mut self, line: &str) -> Option<Vec<Vec<Vec<String>>>> {
        // A trailing backslash from the previous line means line continuation:
        // consume the backslash+newline and continue parsing normally.
        // We reset here (rather than at the end of the previous call) so that
        // `is_continuation()` returns true between the two calls.
        if self.state == State::Escape {
            self.state = State::Normal;
        }

        for c in line.chars() {
            self.process_char(c);
        }

        match self.state {
            State::Normal | State::PendingAmpersand => {
                // A trailing lone '&' at end-of-line: emit it as a literal.
                if self.state == State::PendingAmpersand {
                    self.current_token.push('&');
                    self.state = State::Normal;
                }
                self.finish_pipeline();
                if self.pipelines.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut self.pipelines))
                }
            }
            _ => None,
        }
    }
}
