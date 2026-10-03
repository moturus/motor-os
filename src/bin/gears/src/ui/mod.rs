pub mod line;
pub mod select;
pub mod tui;
pub mod tui_editor;

use crate::runtime::Runtime;
use crate::session::ToolState;

pub(crate) fn parse_tool_action(argument: &str) -> Result<(&str, ToolState, bool), String> {
    let parts = argument.split_whitespace().collect::<Vec<_>>();
    let ([action, name] | [action, name, "--global"]) = parts.as_slice() else {
        return Err("usage: /tool enable|disable|reset NAME [--global]".to_string());
    };
    let state = match *action {
        "enable" => ToolState::Enabled,
        "disable" => ToolState::Disabled,
        "reset" => ToolState::Inherit,
        _ => return Err("usage: /tool enable|disable|reset NAME [--global]".to_string()),
    };
    Ok((name, state, parts.len() == 3))
}

pub(crate) fn format_tools(runtime: &Runtime) -> Result<String, String> {
    let tools = runtime.tool_statuses()?;
    if tools.is_empty() {
        return Ok("no directory tools configured".to_string());
    }
    Ok(tools
        .iter()
        .map(|tool| {
            format!(
                "{}: {} ({}){}",
                tool.name,
                if tool.enabled { "enabled" } else { "disabled" },
                tool.source,
                if tool.available {
                    ""
                } else {
                    ", unavailable here"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub(crate) fn selection_and_default(argument: &str) -> (&str, bool) {
    let argument = argument.trim();
    if argument == "--default" {
        ("", true)
    } else if let Some(selection) = argument.strip_suffix(" --default") {
        (selection.trim(), true)
    } else {
        (argument, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_command_grammar_is_strict() {
        assert_eq!(
            parse_tool_action("enable sh --global").unwrap(),
            ("sh", ToolState::Enabled, true)
        );
        assert_eq!(
            parse_tool_action("reset sh").unwrap(),
            ("sh", ToolState::Inherit, false)
        );
        for invalid in [
            "",
            "enable",
            "enable sh extra",
            "enable --global sh",
            "other sh",
        ] {
            assert!(parse_tool_action(invalid).is_err(), "{invalid}");
        }
    }
}
