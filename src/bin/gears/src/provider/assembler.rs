//! Streamed chunks in, one [`Completion`] out.
//!
//! The dialect delivers a turn as fragments: text a token at a time, tool
//! calls as an id and a name followed by argument text in pieces, and usage
//! in a final chunk. Reassembly is keyed by the tool call's `index`, which is
//! what keeps parallel calls apart while their fragments interleave.

use super::wire::{ApiError, StreamChunk};
use super::{Completion, EventSink, FinishReason, ProviderError, StreamEvent, ToolCall, Usage};

#[derive(Default)]
pub struct DeltaAssembler {
    content: String,
    reasoning: String,
    calls: Vec<PartialCall>,
    finish_reason: Option<FinishReason>,
    usage: Option<Usage>,
    model: Option<String>,
    done: bool,
}

struct PartialCall {
    index: usize,
    id: String,
    name: String,
    arguments: String,
}

impl DeltaAssembler {
    pub fn new() -> DeltaAssembler {
        DeltaAssembler::default()
    }

    /// Absorb one chunk, streaming any text it carried to `sink`.
    pub fn push(
        &mut self,
        chunk: StreamChunk,
        sink: &mut dyn EventSink,
    ) -> Result<(), ProviderError> {
        if let Some(error) = &chunk.error {
            return Err(mid_stream_error(error));
        }
        if self.model.is_none() {
            self.model = chunk.model;
        }
        if chunk.usage.is_some() {
            self.usage = chunk.usage;
        }

        // gears never asks for more than one choice; a second one would be a
        // parallel sample, not part of this turn.
        for choice in chunk.choices.into_iter().filter(|c| c.index == 0) {
            let delta = choice.delta;
            if let Some(text) = delta.content.filter(|t| !t.is_empty()) {
                self.content.push_str(&text);
                sink.on_event(StreamEvent::Text(text.clone()))
                    .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            }
            if let Some(text) = delta.reasoning.filter(|t| !t.is_empty()) {
                self.reasoning.push_str(&text);
                sink.on_event(StreamEvent::Reasoning(text.clone()))
                    .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            }
            for fragment in &delta.tool_calls {
                let slot = self.slot(fragment.index);
                if let Some(id) = fragment.id.as_deref().filter(|id| !id.is_empty())
                    && slot.id.is_empty()
                {
                    slot.id = id.to_string();
                }
                let Some(function) = &fragment.function else {
                    continue;
                };
                // The name arrives whole in the first fragment for this
                // index; later repeats of it are the same string again.
                if let Some(name) = function.name.as_deref().filter(|n| !n.is_empty())
                    && slot.name.is_empty()
                {
                    slot.name = name.to_string();
                }
                if let Some(arguments) = &function.arguments {
                    slot.arguments.push_str(arguments);
                }
            }
            if let Some(reason) = choice.finish_reason.filter(|r| !r.is_empty()) {
                self.finish_reason = Some(FinishReason::parse(&reason));
            }
        }
        Ok(())
    }

    /// Note the `[DONE]` sentinel: proof the stream ended on purpose.
    pub fn mark_done(&mut self) {
        self.done = true;
    }

    pub fn finish(self) -> Result<Completion, ProviderError> {
        // Neither a finish reason nor the sentinel means the connection ended
        // mid-turn, and the text so far is a fragment of an answer.
        if self.finish_reason.is_none() && !self.done {
            return Err(ProviderError::Truncated(format!(
                "the stream ended after {} characters with no finish reason",
                self.content.chars().count()
            )));
        }

        let mut calls = self.calls;
        calls.sort_by_key(|call| call.index);
        let mut tool_calls = Vec::with_capacity(calls.len());
        for call in calls {
            if call.name.is_empty() {
                return Err(ProviderError::Protocol(format!(
                    "tool call {} arrived without a name",
                    call.index
                )));
            }
            // An id is how the result is addressed back; endpoints that omit
            // it get one, since only the round trip has to agree.
            let id = match call.id.is_empty() {
                true => format!("call_{}", call.index),
                false => call.id,
            };
            tool_calls.push(ToolCall::new(id, call.name, call.arguments));
        }

        Ok(Completion {
            content: self.content,
            reasoning: self.reasoning,
            tool_calls,
            finish_reason: self.finish_reason,
            usage: self.usage.unwrap_or_default(),
            model: self.model,
        })
    }

    fn slot(&mut self, index: usize) -> &mut PartialCall {
        match self.calls.iter().position(|call| call.index == index) {
            Some(at) => &mut self.calls[at],
            None => {
                self.calls.push(PartialCall {
                    index,
                    id: String::new(),
                    name: String::new(),
                    arguments: String::new(),
                });
                self.calls.last_mut().expect("just pushed")
            }
        }
    }
}

/// An error the endpoint reported inside the stream. It carries no HTTP
/// status of its own, so one is used only when the body spelled it out.
fn mid_stream_error(error: &ApiError) -> ProviderError {
    match error.status_code() {
        Some(status) => ProviderError::from_status(status, None, error.detail()),
        None => ProviderError::Api {
            status: None,
            detail: error.detail(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects what the UI would have rendered, in delta order.
    #[derive(Default)]
    struct Rendered {
        content: Vec<String>,
        reasoning: Vec<String>,
    }

    impl EventSink for Rendered {
        fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
            match event {
                StreamEvent::Text(text) => self.content.push(text),
                StreamEvent::Reasoning(text) => self.reasoning.push(text),
            }
            Ok(())
        }
    }

    fn run(payloads: &[&str]) -> (Result<Completion, ProviderError>, Rendered) {
        let mut assembler = DeltaAssembler::new();
        let mut rendered = Rendered::default();
        for payload in payloads {
            if *payload == "[DONE]" {
                assembler.mark_done();
                continue;
            }
            let chunk: StreamChunk = serde_json::from_str(payload).expect("test payload");
            if let Err(e) = assembler.push(chunk, &mut rendered) {
                return (Err(e), rendered);
            }
        }
        (assembler.finish(), rendered)
    }

    fn content_delta(text: &str) -> String {
        format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{text}"}}}}]}}"#)
    }

    #[test]
    fn assembles_text_and_streams_it_as_it_arrives() {
        let (completion, rendered) = run(&[
            r#"{"model":"openai/gpt-5","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
            &content_delta("He"),
            &content_delta("llo"),
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":2,"cost":0.0001}}"#,
            "[DONE]",
        ]);

        let completion = completion.unwrap();
        assert_eq!(completion.content, "Hello");
        assert_eq!(completion.finish_reason, Some(FinishReason::Stop));
        assert_eq!(completion.model.as_deref(), Some("openai/gpt-5"));
        assert_eq!(completion.usage.completion_tokens, 2);
        assert_eq!(completion.usage.cost, Some(0.0001));
        // Streamed, not delivered in one lump — and the empty opening delta
        // is not rendered as anything.
        assert_eq!(rendered.content, ["He", "llo"]);
    }

    #[test]
    fn reasoning_streams_separately_and_stays_out_of_the_content() {
        let (completion, rendered) = run(&[
            r#"{"choices":[{"index":0,"delta":{"reasoning":"let me "}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"reasoning_content":"think"}}]}"#,
            &content_delta("done"),
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ]);

        let completion = completion.unwrap();
        assert_eq!(completion.content, "done");
        assert_eq!(completion.reasoning, "let me think");
        assert_eq!(rendered.reasoning, ["let me ", "think"]);
        // Reasoning is for the user, not for the next request.
        assert_eq!(completion.message().text_content(), "done");
    }

    #[test]
    fn parallel_tool_calls_survive_interleaved_fragments() {
        let (completion, rendered) = run(&[
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                 {"index":0,"id":"call_a","type":"function","function":{"name":"read_file","arguments":""}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                 {"index":1,"id":"call_b","type":"function","function":{"name":"grep","arguments":""}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"q\":\"fn "}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"src/main.rs\"}"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"main\"}"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ]);

        let completion = completion.unwrap();
        assert_eq!(completion.finish_reason, Some(FinishReason::ToolCalls));
        assert!(completion.wants_tools());
        assert_eq!(completion.tool_calls.len(), 2);
        assert_eq!(completion.tool_calls[0].id, "call_a");
        assert_eq!(completion.tool_calls[0].name, "read_file");
        assert_eq!(
            completion.tool_calls[0].arguments,
            r#"{"path":"src/main.rs"}"#
        );
        assert_eq!(completion.tool_calls[1].id, "call_b");
        assert_eq!(completion.tool_calls[1].name, "grep");
        assert_eq!(completion.tool_calls[1].arguments, r#"{"q":"fn main"}"#);
        assert!(rendered.content.is_empty());

        // The argument JSON is intact, which is what dispatch needs.
        let parsed: serde_json::Value =
            serde_json::from_str(&completion.tool_calls[1].arguments).unwrap();
        assert_eq!(parsed["q"], "fn main");
    }

    #[test]
    fn calls_come_back_in_index_order_however_they_arrived() {
        let (completion, _) = run(&[
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                 {"index":2,"id":"c2","function":{"name":"third","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                 {"index":0,"function":{"name":"first","arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        ]);

        let calls = completion.unwrap().tool_calls;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "first");
        assert_eq!(calls[1].name, "third");
        // An endpoint that sent no id still gets an addressable call.
        assert_eq!(calls[0].id, "call_0");
    }

    #[test]
    fn a_second_choice_is_not_part_of_this_turn() {
        let (completion, _) = run(&[
            &content_delta("mine"),
            r#"{"choices":[{"index":1,"delta":{"content":"someone else's"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ]);
        assert_eq!(completion.unwrap().content, "mine");
    }

    #[test]
    fn a_cut_stream_is_truncated_not_a_short_answer() {
        let (completion, rendered) = run(&[&content_delta("half an ans")]);
        assert!(
            matches!(completion, Err(ProviderError::Truncated(_))),
            "{completion:?}"
        );
        // The user saw the partial text; the caller still learns it was cut.
        assert_eq!(rendered.content, ["half an ans"]);

        // The sentinel alone is enough, for endpoints that send no reason.
        let (completion, _) = run(&[&content_delta("all of it"), "[DONE]"]);
        assert_eq!(completion.unwrap().content, "all of it");
    }

    #[test]
    fn a_mid_stream_error_stops_the_turn() {
        let (completion, _) = run(&[
            &content_delta("starting"),
            r#"{"error":{"message":"upstream is overloaded","code":502}}"#,
            "[DONE]",
        ]);
        assert!(
            matches!(completion, Err(ProviderError::Unavailable(_))),
            "{completion:?}"
        );

        // With no status in the body there is none to report.
        let (completion, _) = run(&[r#"{"error":{"message":"something went wrong"}}"#]);
        assert_eq!(
            completion.unwrap_err().to_string(),
            "provider error: something went wrong"
        );
    }

    #[test]
    fn a_nameless_tool_call_is_a_protocol_error() {
        let (completion, _) = run(&[
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        ]);
        assert!(
            matches!(completion, Err(ProviderError::Protocol(_))),
            "{completion:?}"
        );
    }

    #[test]
    fn a_sink_refusal_cancels_the_turn() {
        struct Refuse;
        impl EventSink for Refuse {
            fn on_event(&mut self, _event: StreamEvent) -> std::io::Result<()> {
                Err(std::io::Error::other("^C"))
            }
        }

        let mut assembler = DeltaAssembler::new();
        let chunk: StreamChunk = serde_json::from_str(&content_delta("x")).unwrap();
        let error = assembler.push(chunk, &mut Refuse).unwrap_err();
        assert!(matches!(error, ProviderError::Aborted(_)), "{error}");
    }
}
