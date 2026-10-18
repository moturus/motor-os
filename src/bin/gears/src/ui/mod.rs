mod history;
pub mod jsonl;
pub mod line;
pub mod select;
pub mod tui;
pub mod tui_editor;

use crate::runtime::{Approver, Observer, Runtime};
use crate::session::ToolState;

enum Operation {
    Turn(String),
    HookCommand { name: String, argument: String },
    Questions,
}

impl Operation {
    fn run(
        self,
        runtime: &mut Runtime,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        match self {
            Self::Turn(prompt) => runtime.turn(prompt, approver, observer),
            Self::HookCommand { name, argument } => {
                runtime.hook_command_with_approver(&name, &argument, approver, observer)
            }
            Self::Questions => runtime.resolve_hook_questions(approver, observer),
        }
    }
}

fn question_answer(
    question: &crate::hooks::Question,
    answer: Option<&str>,
) -> Result<Option<String>, String> {
    let answer = answer.unwrap_or_default().trim();
    if answer.is_empty() {
        return Ok(None);
    }
    if let Some(choice) = question
        .choices
        .iter()
        .find(|choice| choice.value == answer)
    {
        return Ok(Some(choice.value.clone()));
    }
    if let Ok(number) = answer.parse::<usize>()
        && let Some(choice) = number
            .checked_sub(1)
            .and_then(|index| question.choices.get(index))
    {
        return Ok(Some(choice.value.clone()));
    }
    Err("choose a listed answer, or press Enter to skip".into())
}

pub(crate) fn help(runtime: &Runtime) -> String {
    let mut text = crate::cli::USAGE.to_string();
    for command in runtime.hook_commands() {
        text.push_str(&format!("/{} - {}\n", command.name, command.help));
    }
    text
}

/// Models to offer: the provider's own list, then the configured `[models] used`.
pub(crate) fn model_choices(config: &crate::config::Config, provider: &str) -> Vec<String> {
    let mut models = config
        .provider(provider)
        .map(|provider| provider.models)
        .unwrap_or_default();
    for model in &config.models {
        if !models.contains(model) {
            models.push(model.clone());
        }
    }
    models
}

/// Setup sees the provider addresses saved since the configuration loaded.
pub(crate) fn current_config(
    config: &crate::config::Config,
) -> Result<crate::config::Config, String> {
    let mut config = config.clone();
    if let Some(choice) = crate::provider_choice::ProviderChoice::load_default()? {
        config.apply_urls(&choice.urls)?;
    }
    Ok(config)
}

pub(crate) fn reset_notice(removed: usize) -> String {
    format!(
        "Gears was reset ({removed} entries removed). This run keeps its provider, model and key until Gears restarts."
    )
}

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
