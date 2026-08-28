//! OpenAI-compatible response shapes. These never cross the adapter boundary.

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct StreamChunk {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub choices: Vec<StreamChoice>,
    #[serde(default)]
    pub usage: Option<super::Usage>,
    #[serde(default)]
    pub error: Option<ApiError>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct StreamChoice {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub delta: Delta,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct Delta {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(
        default,
        alias = "reasoning_content",
        deserialize_with = "lenient_text"
    )]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallDelta>,
    #[serde(flatten)]
    pub _extra: Map<String, Value>,
}

fn lenient_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::String(text) => Some(text),
        _ => None,
    })
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct ToolCallDelta {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub function: Option<FunctionDelta>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct FunctionDelta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub(super) struct ApiError {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub code: Option<Value>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ApiError,
}

impl ApiError {
    pub fn from_body(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<ErrorEnvelope>(bytes)
            .ok()
            .map(|envelope| envelope.error)
    }

    pub fn status_code(&self) -> Option<u16> {
        let number = match self.code.as_ref()? {
            Value::Number(number) => number.as_u64()?,
            Value::String(text) => text.parse().ok()?,
            _ => return None,
        };
        u16::try_from(number)
            .ok()
            .filter(|status| (100..600).contains(status))
    }

    pub fn detail(&self) -> String {
        let mut text = if self.message.is_empty() {
            "the endpoint reported an error".to_string()
        } else {
            self.message.clone()
        };
        match (&self.kind, &self.code) {
            (Some(kind), _) => text.push_str(&format!(" ({kind})")),
            (None, Some(code)) => text.push_str(&format!(" (code {code})")),
            (None, None) => {}
        }
        text
    }
}
