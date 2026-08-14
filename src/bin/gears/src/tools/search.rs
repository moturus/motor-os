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
}
