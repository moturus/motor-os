//! Provider-neutral conversation and streaming types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cancellation::Cancellation;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    Tool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolCall {
        call: ToolCall,
    },
    ToolResult {
        call_id: String,
        tool_name: String,
        content: String,
        is_error: bool,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user(text: impl Into<String>) -> Self {
        Self::text(Role::User, text)
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self::text(Role::Assistant, text)
    }

    pub fn assistant_response(text: String, calls: Vec<ToolCall>) -> Self {
        let mut content = Vec::with_capacity(usize::from(!text.is_empty()) + calls.len());
        if !text.is_empty() {
            content.push(ContentBlock::Text { text });
        }
        content.extend(
            calls
                .into_iter()
                .map(|call| ContentBlock::ToolCall { call }),
        );
        Self {
            role: Role::Assistant,
            content,
        }
    }

    pub fn tool_result(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        content: impl Into<String>,
        is_error: bool,
    ) -> Self {
        Self {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                call_id: call_id.into(),
                tool_name: tool_name.into(),
                content: content.into(),
                is_error,
            }],
        }
    }

    fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: vec![ContentBlock::Text { text: text.into() }],
        }
    }

    pub fn text_content(&self) -> String {
        self.content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text { text } => Some(text.as_str()),
                ContentBlock::ToolResult { content, .. } => Some(content.as_str()),
                ContentBlock::ToolCall { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn tool_calls(&self) -> impl Iterator<Item = &ToolCall> {
        self.content.iter().filter_map(|block| match block {
            ContentBlock::ToolCall { call } => Some(call),
            _ => None,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Raw JSON text is retained so malformed model output can be returned as
    /// a tool error instead of becoming a provider protocol error.
    pub arguments: String,
}

impl ToolCall {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments: arguments.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

impl ToolSpec {
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub model: String,
    pub system: Vec<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_output_tokens: Option<u32>,
    pub(crate) cancellation: Option<Cancellation>,
}

impl Request {
    pub fn new(model: impl Into<String>, messages: Vec<Message>) -> Self {
        Self {
            model: model.into(),
            system: Vec::new(),
            messages,
            tools: Vec::new(),
            max_output_tokens: None,
            cancellation: None,
        }
    }

    pub fn with_system(mut self, system: Vec<String>) -> Self {
        self.system = system;
        self
    }

    pub fn with_tools(mut self, tools: Vec<ToolSpec>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
}

impl Usage {
    pub fn total(&self) -> u64 {
        if self.total_tokens == 0 {
            self.prompt_tokens + self.completion_tokens
        } else {
            self.total_tokens
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolCalls,
    Length,
    ContentFilter,
    Other(String),
}

impl FinishReason {
    pub(crate) fn parse(text: &str) -> Self {
        match text {
            "stop" | "end_turn" => Self::Stop,
            "tool_calls" | "function_call" => Self::ToolCalls,
            "length" | "max_tokens" => Self::Length,
            "content_filter" => Self::ContentFilter,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Completion {
    pub content: String,
    pub reasoning: String,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<FinishReason>,
    pub usage: Usage,
    pub model: Option<String>,
}

impl Completion {
    pub fn message(&self) -> Message {
        Message::assistant_response(self.content.clone(), self.tool_calls.clone())
    }

    pub fn wants_tools(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Text(String),
    Reasoning(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_content_block_based() {
        let message = Message::assistant_response(
            "working".to_string(),
            vec![ToolCall::new("one", "sh", r#"{"command":"true"}"#)],
        );
        assert_eq!(message.text_content(), "working");
        assert_eq!(message.tool_calls().next().unwrap().name, "sh");
        assert_eq!(
            serde_json::to_value(&message).unwrap()["content"][1]["type"],
            "tool_call"
        );
    }

    #[test]
    fn usage_uses_the_reported_total_when_present() {
        assert_eq!(
            Usage {
                prompt_tokens: 2,
                completion_tokens: 3,
                ..Usage::default()
            }
            .total(),
            5
        );
        assert_eq!(
            Usage {
                total_tokens: 9,
                ..Usage::default()
            }
            .total(),
            9
        );
    }
}
