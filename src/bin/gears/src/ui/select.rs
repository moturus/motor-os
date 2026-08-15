//! UI selection without initializing either implementation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requested {
    Auto,
    Tui,
    Line,
}

impl Requested {
    pub fn parse(name: &str) -> Result<Requested, String> {
        match name {
            "auto" => Ok(Requested::Auto),
            "tui" => Ok(Requested::Tui),
            "line" => Ok(Requested::Line),
            _ => Err(format!("unknown UI '{name}' (expected auto, tui, or line)")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selected {
    Tui,
    Line,
}

/// Select a UI. `terminals` is lazy so explicit line mode and one-shot auto
/// mode perform no terminal query at all.
pub fn choose(
    requested: Requested,
    one_shot: bool,
    terminals: impl FnOnce() -> (bool, bool),
) -> Result<Selected, String> {
    match requested {
        Requested::Line => Ok(Selected::Line),
        Requested::Auto if one_shot => Ok(Selected::Line),
        Requested::Auto => {
            let (input, output) = terminals();
            Ok(match input && output {
                true => Selected::Tui,
                false => Selected::Line,
            })
        }
        Requested::Tui => {
            let (input, output) = terminals();
            if input && output {
                Ok(Selected::Tui)
            } else {
                Err("--ui tui requires terminal input and output; use --ui line".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_exact() {
        assert_eq!(Requested::parse("auto"), Ok(Requested::Auto));
        assert_eq!(Requested::parse("tui"), Ok(Requested::Tui));
        assert_eq!(Requested::parse("line"), Ok(Requested::Line));
        assert!(Requested::parse("terminal").is_err());
    }

    #[test]
    fn line_and_one_shot_auto_make_no_terminal_query() {
        let unexpected = || panic!("terminal query must remain lazy");
        assert_eq!(
            choose(Requested::Line, false, unexpected),
            Ok(Selected::Line)
        );
        assert_eq!(
            choose(Requested::Auto, true, unexpected),
            Ok(Selected::Line)
        );
    }

    #[test]
    fn auto_needs_both_terminal_sides() {
        assert_eq!(
            choose(Requested::Auto, false, || (true, true)),
            Ok(Selected::Tui)
        );
        for terminals in [(false, false), (false, true), (true, false)] {
            assert_eq!(
                choose(Requested::Auto, false, || terminals),
                Ok(Selected::Line)
            );
        }
    }

    #[test]
    fn forced_tui_refuses_an_unsuitable_terminal() {
        let error = choose(Requested::Tui, false, || (true, false)).unwrap_err();
        assert!(error.contains("terminal input and output"), "{error}");
        assert!(error.contains("--ui line"), "{error}");
    }
}
