//! The wire types of the OpenAI-compatible chat-completions dialect.
//!
//! Requests are written exactly; responses are read *tolerantly*. Endpoints
//! differ in what they add to a delta, and a field gears has never heard of
//! must not break a stream — unknown fields are kept in an `extra` map rather
//! than rejected or silently dropped, and `serde_json::Value` passthrough
//! carries endpoint-specific request fields the other way.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

// ---- requests --------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct FunctionCall {
    pub name: String,
    /// A JSON *string*, not an object: it arrives in fragments, and models do
    /// emit invalid JSON. Decoding happens at dispatch, where a failure can
    /// be handed back to the model as a tool error.
    pub arguments: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "function_kind")]
    pub kind: String,
    pub function: FunctionCall,
}

fn function_kind() -> String {
    "function".to_string()
}

impl ToolCall {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        ToolCall {
            id: id.into(),
            kind: function_kind(),
            function: FunctionCall {
                name: name.into(),
                arguments: arguments.into(),
            },
        }
    }

    pub fn name(&self) -> &str {
        &self.function.name
    }

    pub fn arguments(&self) -> &str {
        &self.function.arguments
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// On a `tool` message: which call this answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Internal context policy. Session journals persist this separately;
    /// provider requests must never acquire a non-standard message field.
    #[serde(skip)]
    pub(crate) artifact_reference: bool,
}

impl ChatMessage {
    fn text(role: Role, content: impl Into<String>) -> Self {
        ChatMessage {
            role,
            content: Some(content.into()),
            tool_calls: Vec::new(),
            tool_call_id: None,
            artifact_reference: false,
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        ChatMessage::text(Role::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        ChatMessage::text(Role::User, content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        ChatMessage::text(Role::Assistant, content)
    }

    /// The result of one tool call, addressed to the call it answers.
    pub fn tool_result(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        ChatMessage {
            tool_call_id: Some(call_id.into()),
            ..ChatMessage::text(Role::Tool, content)
        }
    }

    pub(crate) fn retaining_artifact(mut self) -> Self {
        self.artifact_reference = true;
        self
    }

    pub(crate) fn retains_artifact(&self) -> bool {
        self.artifact_reference
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ToolFunction {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// A JSON Schema object describing the arguments.
    pub parameters: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ToolSpec {
    #[serde(rename = "type", default = "function_kind")]
    pub kind: String,
    pub function: ToolFunction,
}

impl ToolSpec {
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        ToolSpec {
            kind: function_kind(),
            function: ToolFunction {
                name: name.into(),
                description: description.into(),
                parameters,
            },
        }
    }
}

/// One completion request. `stream` and the endpoint's usage knob are not
/// here: the client adds them, because which one to send is a quirk of the
/// endpoint rather than a choice of the caller.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Endpoint-specific fields merged into the request object verbatim
    /// (`provider`, `reasoning`, `transforms`, …). gears never interprets
    /// them, which is what keeps one client usable across endpoints.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ChatRequest {
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        ChatRequest {
            model: model.into(),
            messages,
            tools: Vec::new(),
            temperature: None,
            max_tokens: None,
            extra: Map::new(),
        }
    }

    pub fn with_tools(mut self, tools: Vec<ToolSpec>) -> Self {
        self.tools = tools;
        self
    }
}

// ---- streamed responses ----------------------------------------------------

/// One `data:` payload of a streamed completion.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct StreamChunk {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub choices: Vec<StreamChoice>,
    /// Present in the final chunk when usage was requested.
    #[serde(default)]
    pub usage: Option<Usage>,
    /// Some endpoints report a mid-stream failure as a data event rather than
    /// by hanging up.
    #[serde(default)]
    pub error: Option<ApiError>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct StreamChoice {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub delta: Delta,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Delta {
    #[serde(default)]
    pub content: Option<String>,
    /// Reasoning text. The leakiest field in the dialect — spelled two ways,
    /// and an object at some endpoints — so it is read leniently and dropped
    /// rather than allowed to fail a stream.
    #[serde(
        default,
        alias = "reasoning_content",
        deserialize_with = "lenient_text"
    )]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallDelta>,
    /// Everything else the endpoint sent: `role`, `refusal`, vendor
    /// extensions. Kept so nothing is dropped without a trace.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Accept a JSON string; ignore any other shape.
fn lenient_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(text) => Some(text),
        _ => None,
    })
}

/// A fragment of a tool call. The first one for an index carries the id and
/// the name; the rest carry pieces of the argument string.
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ToolCallDelta {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub function: Option<FunctionDelta>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct FunctionDelta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
    /// USD, when the endpoint reports it (OpenRouter does; the generic
    /// dialect does not). Spend budgets fall back to token counts without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
}

impl Usage {
    /// The endpoint's total, or the sum when it reported none.
    pub fn total(&self) -> u64 {
        match self.total_tokens {
            0 => self.prompt_tokens + self.completion_tokens,
            total => total,
        }
    }
}

/// The `{"error": {...}}` envelope both dialects use for failures.
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ApiError {
    #[serde(default)]
    pub message: String,
    /// A number at OpenRouter, a string at OpenAI: kept as it came.
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
    /// Read an error body. `None` means it was not one — an endpoint answering
    /// a failure with HTML or nothing at all.
    pub fn from_body(bytes: &[u8]) -> Option<ApiError> {
        serde_json::from_slice::<ErrorEnvelope>(bytes)
            .ok()
            .map(|envelope| envelope.error)
    }

    /// The HTTP status the body spelled out, if it did. OpenRouter sends a
    /// number here, OpenAI a name like `invalid_api_key`.
    pub fn status_code(&self) -> Option<u16> {
        let code = self.code.as_ref()?;
        let number = match code {
            Value::Number(number) => number.as_u64()?,
            Value::String(text) => text.parse().ok()?,
            _ => return None,
        };
        u16::try_from(number)
            .ok()
            .filter(|s| (100..600).contains(s))
    }

    /// A one-line description for an error message.
    pub fn detail(&self) -> String {
        let mut text = match self.message.is_empty() {
            true => "the endpoint reported an error".to_string(),
            false => self.message.clone(),
        };
        match (&self.kind, &self.code) {
            (Some(kind), _) => text.push_str(&format!(" ({kind})")),
            (None, Some(code)) => text.push_str(&format!(" (code {code})")),
            (None, None) => {}
        }
        text
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    ToolCalls,
    Length,
    ContentFilter,
    Other(String),
}

impl FinishReason {
    pub fn parse(text: &str) -> FinishReason {
        match text {
            "stop" | "end_turn" => FinishReason::Stop,
            "tool_calls" | "function_call" => FinishReason::ToolCalls,
            "length" | "max_tokens" => FinishReason::Length,
            "content_filter" => FinishReason::ContentFilter,
            other => FinishReason::Other(other.to_string()),
        }
    }
}

/// One assembled model turn.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Completion {
    pub content: String,
    /// Reasoning text, empty unless the endpoint streamed it.
    pub reasoning: String,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<FinishReason>,
    pub usage: Usage,
    /// What the endpoint says it actually served, which can differ from the
    /// requested id (routing, dated snapshots).
    pub model: Option<String>,
}

impl Completion {
    /// The assistant turn to append to the conversation. Reasoning is left
    /// out: it is for the user's eyes, not the next request.
    pub fn message(&self) -> ChatMessage {
        ChatMessage {
            role: Role::Assistant,
            content: (!self.content.is_empty()).then(|| self.content.clone()),
            tool_calls: self.tool_calls.clone(),
            tool_call_id: None,
            artifact_reference: false,
        }
    }

    pub fn wants_tools(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_serializes_to_the_wire_shape() {
        let request = ChatRequest::new(
            "anthropic/claude-sonnet-4.5",
            vec![ChatMessage::system("be brief"), ChatMessage::user("hello")],
        );
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"model":"anthropic/claude-sonnet-4.5","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hello"}]}"#
        );
    }

    #[test]
    fn tools_and_tool_results_serialize_to_the_wire_shape() {
        let mut request = ChatRequest::new(
            "m",
            vec![
                ChatMessage {
                    role: Role::Assistant,
                    content: None,
                    tool_calls: vec![ToolCall::new("call_1", "read_file", r#"{"path":"x"}"#)],
                    tool_call_id: None,
                    artifact_reference: false,
                },
                ChatMessage::tool_result("call_1", "file contents").retaining_artifact(),
            ],
        )
        .with_tools(vec![ToolSpec::new(
            "read_file",
            "Read a file.",
            json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        )]);
        request.max_tokens = Some(1024);
        // The passthrough: an endpoint-specific field gears never interprets.
        request
            .extra
            .insert("provider".to_string(), json!({"sort": "throughput"}));

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            concat!(
                r#"{"model":"m","messages":["#,
                r#"{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","#,
                r#""function":{"name":"read_file","arguments":"{\"path\":\"x\"}"}}]},"#,
                r#"{"role":"tool","content":"file contents","tool_call_id":"call_1"}],"#,
                r#""tools":[{"type":"function","function":{"name":"read_file","#,
                r#""description":"Read a file.","parameters":{"properties":{"path":{"type":"string"}},"type":"object"}}}],"#,
                r#""max_tokens":1024,"provider":{"sort":"throughput"}}"#,
            )
        );
    }

    fn chunk(text: &str) -> StreamChunk {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn a_content_delta_parses() {
        let parsed = chunk(
            r#"{"id":"gen-1","model":"openai/gpt-5","choices":[
                 {"index":0,"delta":{"role":"assistant","content":"He"},"finish_reason":null}]}"#,
        );
        assert_eq!(parsed.model.as_deref(), Some("openai/gpt-5"));
        assert_eq!(parsed.choices[0].delta.content.as_deref(), Some("He"));
        assert_eq!(parsed.choices[0].finish_reason, None);
        // `role` is not a field gears models, so it is kept in `extra`; `id`
        // is not a field of the chunk either and is simply ignored.
        assert_eq!(parsed.choices[0].delta.extra["role"], json!("assistant"));
    }

    #[test]
    fn unknown_and_reasoning_delta_fields_survive() {
        let parsed = chunk(
            r#"{"choices":[{"delta":{"content":"x","reasoning":"thinking",
                 "refusal":null,"vendor_thing":{"a":1}}}]}"#,
        );
        let delta = &parsed.choices[0].delta;
        assert_eq!(delta.reasoning.as_deref(), Some("thinking"));
        assert_eq!(delta.extra["vendor_thing"], json!({"a": 1}));
        assert!(delta.extra.contains_key("refusal"));

        // The other spelling, and a shape gears cannot use: neither breaks.
        let parsed = chunk(r#"{"choices":[{"delta":{"reasoning_content":"hm"}}]}"#);
        assert_eq!(parsed.choices[0].delta.reasoning.as_deref(), Some("hm"));
        let parsed = chunk(r#"{"choices":[{"delta":{"reasoning":{"text":"hm"}}}]}"#);
        assert_eq!(parsed.choices[0].delta.reasoning, None);
    }

    #[test]
    fn a_tool_call_delta_parses_in_fragments() {
        let parsed = chunk(
            r#"{"choices":[{"delta":{"tool_calls":[
                 {"index":0,"id":"call_1","type":"function",
                  "function":{"name":"grep","arguments":""}}]}}]}"#,
        );
        let call = &parsed.choices[0].delta.tool_calls[0];
        assert_eq!(call.index, 0);
        assert_eq!(call.id.as_deref(), Some("call_1"));
        assert_eq!(
            call.function.as_ref().unwrap().name.as_deref(),
            Some("grep")
        );

        // A continuation carries neither id nor name.
        let parsed = chunk(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,
                             "function":{"arguments":"{\"q\":"}}]}}]}"#,
        );
        let call = &parsed.choices[0].delta.tool_calls[0];
        assert_eq!(call.id, None);
        assert_eq!(
            call.function.as_ref().unwrap().arguments.as_deref(),
            Some("{\"q\":")
        );
    }

    #[test]
    fn a_sparse_chunk_parses() {
        // Empty deltas, absent choices and explicit nulls all appear on the
        // wire; none of them is an error.
        assert!(
            chunk(r#"{"choices":[{"delta":{}}]}"#).choices[0]
                .delta
                .content
                .is_none()
        );
        assert!(chunk(r#"{"choices":[]}"#).choices.is_empty());
        assert!(
            chunk(r#"{"usage":null,"choices":[{"delta":{"content":null}}]}"#)
                .usage
                .is_none()
        );
        assert!(chunk(r#"{}"#).choices.is_empty());
    }

    #[test]
    fn usage_parses_with_and_without_cost() {
        let parsed = chunk(
            r#"{"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":22,
                 "total_tokens":33,"cost":0.000123}}"#,
        );
        let usage = parsed.usage.unwrap();
        assert_eq!(usage.cost, Some(0.000123));
        assert_eq!(usage.total(), 33);

        let parsed = chunk(r#"{"usage":{"prompt_tokens":2,"completion_tokens":3}}"#);
        let usage = parsed.usage.unwrap();
        assert_eq!(usage.cost, None);
        assert_eq!(usage.total(), 5);
    }

    #[test]
    fn error_bodies_of_both_dialects_parse() {
        let openrouter =
            ApiError::from_body(br#"{"error":{"message":"Insufficient credits","code":402}}"#)
                .unwrap();
        assert_eq!(openrouter.detail(), "Insufficient credits (code 402)");

        let openai = ApiError::from_body(
            br#"{"error":{"message":"Bad key","type":"invalid_request_error","code":"invalid_api_key"}}"#,
        )
        .unwrap();
        assert_eq!(openai.detail(), "Bad key (invalid_request_error)");

        // A mid-stream error event uses the same envelope.
        let parsed = chunk(r#"{"error":{"message":"upstream is overloaded"},"choices":[]}"#);
        assert_eq!(parsed.error.unwrap().detail(), "upstream is overloaded");

        assert_eq!(ApiError::from_body(b"<html>502</html>"), None);
        assert_eq!(ApiError::from_body(b""), None);

        // A status is used only where the body really carried one.
        assert_eq!(openrouter.status_code(), Some(402));
        assert_eq!(openai.status_code(), None);
        assert_eq!(ApiError::default().status_code(), None);
    }

    #[test]
    fn finish_reasons_map_to_causes() {
        assert_eq!(FinishReason::parse("stop"), FinishReason::Stop);
        assert_eq!(FinishReason::parse("end_turn"), FinishReason::Stop);
        assert_eq!(FinishReason::parse("tool_calls"), FinishReason::ToolCalls);
        assert_eq!(FinishReason::parse("length"), FinishReason::Length);
        assert_eq!(
            FinishReason::parse("guardrail"),
            FinishReason::Other("guardrail".to_string())
        );
    }

    #[test]
    fn a_completion_becomes_the_next_assistant_message() {
        let completion = Completion {
            content: "on it".to_string(),
            reasoning: "not sent back".to_string(),
            tool_calls: vec![ToolCall::new("call_1", "read_file", "{}")],
            ..Completion::default()
        };
        let message = completion.message();
        assert_eq!(message.role, Role::Assistant);
        assert_eq!(message.content.as_deref(), Some("on it"));
        assert_eq!(message.tool_calls, completion.tool_calls);
        assert!(completion.wants_tools());

        // Tool calls with no text: `content` is absent, not empty.
        let completion = Completion {
            tool_calls: vec![ToolCall::new("call_1", "grep", "{}")],
            ..Completion::default()
        };
        assert_eq!(completion.message().content, None);
    }
}
