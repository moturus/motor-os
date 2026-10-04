//! Display the saved active branch without replaying runtime operations.

use crate::provider::{ContentBlock, Message, Role};
use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    User,
    Assistant,
    Reasoning,
    Tool,
    ToolOutput,
    Notice,
    Error,
}

pub(super) fn replay(
    session: &Session,
    mut show: impl FnMut(Kind, String) -> Result<(), String>,
) -> Result<(), String> {
    // Model context replaces old messages at compaction; the visible history
    // retains them and excludes entries from abandoned branches.
    for entry in session.active_entries()? {
        match entry.kind.as_str() {
            "message" => {
                let message: Message = serde_json::from_value(entry.data)
                    .map_err(|error| format!("entry {}: bad message: {error}", entry.id))?;
                if let Some(reasoning) = message.reasoning {
                    show(Kind::Reasoning, reasoning)?;
                }
                for block in message.content {
                    match block {
                        ContentBlock::Text { text } => show(
                            match message.role {
                                Role::User => Kind::User,
                                Role::Assistant => Kind::Assistant,
                                Role::Tool => Kind::Tool,
                            },
                            text,
                        )?,
                        ContentBlock::ToolCall { call } => {
                            show(Kind::Tool, format!("{}> {}", call.name, call.arguments))?;
                        }
                        ContentBlock::ToolResult {
                            tool_name,
                            content,
                            is_error,
                            ..
                        } => {
                            let content = content.trim();
                            let detail = if content.len() <= 200 && !content.contains('\n') {
                                content.to_string()
                            } else {
                                format!("{} bytes", content.len())
                            };
                            show(
                                if is_error { Kind::Error } else { Kind::Tool },
                                format!("{tool_name}> {detail}"),
                            )?;
                        }
                    }
                }
            }
            "turn_error" => {
                if let Some(detail) = entry.data["detail"].as_str() {
                    show(Kind::Error, detail.to_string())?;
                }
            }
            "compaction" => show(
                Kind::Notice,
                "conversation compacted; history retained".into(),
            )?,
            _ => {}
        }
    }
    Ok(())
}
