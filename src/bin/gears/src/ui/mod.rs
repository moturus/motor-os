pub mod jsonl;
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

pub(crate) fn parse_permission_action(argument: &str) -> Result<(&str, bool), String> {
    let parts = argument.split_whitespace().collect::<Vec<_>>();
    let (["revoke", name] | ["revoke", name, "--global"]) = parts.as_slice() else {
        return Err("usage: /permission revoke NAME [--global]".to_string());
    };
    Ok((name, parts.len() == 3))
}

pub(crate) fn format_permissions(runtime: &Runtime) -> Result<String, String> {
    let grants = runtime.permission_statuses()?;
    if grants.is_empty() {
        return Ok("no saved permissions".to_string());
    }
    Ok(grants
        .iter()
        .map(|grant| {
            format!(
                "{}: {} {} [{}] {}{}",
                grant.name,
                grant.scope,
                if grant.allow { "allow" } else { "deny" },
                &grant.identity[..12],
                if grant.current { "current" } else { "stale" },
                grant
                    .identity_error
                    .as_ref()
                    .map_or(String::new(), |error| {
                        format!("; identity unavailable: {error}")
                    })
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

    #[test]
    fn permission_command_grammar_is_strict() {
        assert_eq!(parse_permission_action("revoke sh").unwrap(), ("sh", false));
        assert_eq!(
            parse_permission_action("revoke sh --global").unwrap(),
            ("sh", true)
        );
        for invalid in ["", "revoke", "revoke sh extra", "revoke --global sh"] {
            assert!(parse_permission_action(invalid).is_err(), "{invalid}");
        }
    }
}
