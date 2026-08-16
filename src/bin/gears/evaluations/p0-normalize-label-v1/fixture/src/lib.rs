/// Collapse whitespace runs to one ASCII space for a stable display label.
pub fn normalize_label(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut in_whitespace = false;
    for character in input.chars() {
        if character.is_whitespace() {
            if !in_whitespace {
                output.push(' ');
            }
            in_whitespace = true;
        } else {
            output.push(character);
            in_whitespace = false;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_internal_runs() {
        assert_eq!(normalize_label("alpha\t  beta\ngamma"), "alpha beta gamma");
    }

    #[test]
    fn trims_edges() {
        assert_eq!(normalize_label("  alpha beta\n"), "alpha beta");
    }

    #[test]
    fn whitespace_only_is_empty() {
        assert_eq!(normalize_label(" \t\n"), "");
    }
}
