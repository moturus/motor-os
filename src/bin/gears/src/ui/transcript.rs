//! A bounded, terminal-independent view of durable messages and live events.

use std::collections::VecDeque;

use crate::agent::bus::{AgentId, Event, ROOT, ToolStream};
use crate::provider::{ChatMessage, Role};

const MAX_ENTRIES: usize = 4096;
const INLINE_TOOL_RESULT_BYTES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    User,
    Model(AgentId),
    Reasoning(AgentId),
    Tool(AgentId),
    ToolOutput(AgentId, ToolStream),
    Notice(AgentId),
    Failed(AgentId),
    Permission(AgentId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub source: Source,
    pub text: String,
    live: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    entries: VecDeque<Entry>,
    bytes: usize,
    limit: usize,
}

impl Transcript {
    pub fn new(limit: usize) -> Transcript {
        assert!(limit > 0);
        Transcript {
            entries: VecDeque::new(),
            bytes: 0,
            limit,
        }
    }

    pub fn entries(&self) -> &VecDeque<Entry> {
        &self.entries
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn lines(&self) -> usize {
        let content = self
            .entries
            .iter()
            .map(|entry| entry.text.split_terminator('\n').count().max(1))
            .sum::<usize>();
        content + self.entries.len().saturating_sub(1)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    /// Replace live screen state with the durable conversation projection.
    pub fn rebuild(&mut self, messages: &[ChatMessage]) {
        self.clear();
        for message in messages {
            self.record(message);
        }
    }

    pub fn record(&mut self, message: &ChatMessage) {
        match message.role {
            Role::System => {}
            Role::User => {
                self.push(Source::User, message.displayed_content(), false);
            }
            Role::Assistant => {
                self.push(Source::Model(ROOT), message.content.as_deref(), false);
                for call in &message.tool_calls {
                    self.push(
                        Source::Tool(ROOT),
                        Some(&format!("call {} {}", call.name(), call.arguments())),
                        false,
                    );
                }
            }
            Role::Tool => {
                if let Some(content) = message.content.as_deref() {
                    let summary = durable_tool_summary(content);
                    self.push(Source::Tool(ROOT), Some(&summary), false);
                }
            }
        }
    }

    /// Apply one live event. Adjacent streamed chunks are coalesced before
    /// eviction, so a fast producer cannot turn the entry list into a queue of
    /// tiny allocations.
    pub fn apply(&mut self, event: &Event) -> bool {
        let agent = event.agent();
        match event {
            Event::Token { text, .. } => self.push(Source::Model(agent), Some(text), true),
            Event::Reasoning { text, .. } => self.push(Source::Reasoning(agent), Some(text), true),
            Event::ToolStart { detail, .. } => self.push(
                Source::Tool(agent),
                Some(&format!("running {detail}")),
                false,
            ),
            Event::ToolOutput { stream, text, .. } => {
                self.push(Source::ToolOutput(agent, *stream), Some(text), true)
            }
            Event::ToolEnd {
                outcome, detail, ..
            } => {
                let folded = self.fold_tool_output(agent);
                let text = match outcome.is_error() {
                    true => format!("error: {detail}"),
                    false => detail.clone(),
                };
                self.push(Source::Tool(agent), Some(&text), false) || folded
            }
            Event::Permission { request, .. } => self.push(
                Source::Permission(agent),
                Some(&format!("approval requested: {}", request.detail)),
                false,
            ),
            Event::Notice { text, .. } => self.push(Source::Notice(agent), Some(text), false),
            Event::Failed { text, .. } => self.push(Source::Failed(agent), Some(text), false),
            Event::TurnEnd { .. } | Event::Exit { .. } => {
                for entry in &mut self.entries {
                    entry.live = false;
                }
                false
            }
            Event::ToolProgress { .. } => false,
        }
    }

    fn push(&mut self, source: Source, text: Option<&str>, live: bool) -> bool {
        let Some(text) = text.filter(|text| !text.is_empty()) else {
            return false;
        };
        let text: String = crate::trace::scrub(text)
            .chars()
            .map(|character| match character {
                '\n' | '\t' => character,
                control if control.is_control() => '�',
                other => other,
            })
            .collect();
        let merge = live
            && self
                .entries
                .back()
                .is_some_and(|last| last.live && last.source == source);
        if merge {
            let mut last = self.entries.pop_back().expect("live entry disappeared");
            self.bytes -= last.text.len();
            last.text.push_str(&text);
            last.text = suffix(&last.text, self.limit);
            if !last.text.is_empty() {
                self.bytes += last.text.len();
                self.entries.push_back(last);
            }
        } else {
            let text = suffix(&text, self.limit);
            if text.is_empty() {
                return false;
            }
            self.bytes += text.len();
            self.entries.push_back(Entry { source, text, live });
        }
        while self.bytes > self.limit || self.entries.len() > MAX_ENTRIES {
            let removed = self.entries.pop_front().expect("transcript lost its bytes");
            self.bytes -= removed.text.len();
        }
        true
    }

    /// Remove the streamed body of the tool call that just finished. Its
    /// concise `ToolEnd` record remains in the transcript, while the complete
    /// result is retained separately by the UI for explicit expansion.
    fn fold_tool_output(&mut self, agent: AgentId) -> bool {
        let start = self
            .entries
            .iter()
            .rposition(|entry| entry.source == Source::Tool(agent))
            .map_or(0, |index| index + 1);
        let mut changed = false;
        let mut index = start;
        while index < self.entries.len() {
            if matches!(self.entries[index].source, Source::ToolOutput(id, _) if id == agent) {
                let removed = self.entries.remove(index).expect("tool output disappeared");
                self.bytes -= removed.text.len();
                changed = true;
            } else {
                index += 1;
            }
        }
        changed
    }
}

/// Durable messages do not retain a tool's outcome, but they can still obey
/// the live UI's boundary between an inline result and expandable output.
fn durable_tool_summary(text: &str) -> String {
    let content = text.trim_end();
    if content.len() <= INLINE_TOOL_RESULT_BYTES && !content.contains('\n') {
        content.to_string()
    } else {
        format!("{} bytes", text.len())
    }
}

fn suffix(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let marker = "…";
    if limit < marker.len() {
        let mut start = text.len().saturating_sub(limit);
        while start < text.len() && !text.is_char_boundary(start) {
            start += 1;
        }
        return text[start..].to_string();
    }
    let keep = limit.saturating_sub(marker.len());
    let mut start = text.len().saturating_sub(keep);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("{marker}{}", &text[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::ToolStream;
    use crate::provider::ToolCall;

    #[test]
    fn durable_messages_are_projected_without_system_text() {
        let mut assistant = ChatMessage::assistant("answer");
        assistant.tool_calls = vec![ToolCall::new("1", "read_file", r#"{"path":"a"}"#)];
        let messages = [
            ChatMessage::system("secret instructions"),
            ChatMessage::user("provider-only question").with_display_content("question"),
            assistant,
            ChatMessage::tool_result("1", "artifact 7: 90000 bytes"),
        ];
        let mut transcript = Transcript::new(1024);
        transcript.rebuild(&messages);

        assert_eq!(transcript.entries.len(), 4);
        assert_eq!(transcript.entries[0].source, Source::User);
        assert_eq!(transcript.entries[0].text, "question");
        assert!(transcript.entries[2].text.contains("read_file"));
        assert!(transcript.entries[3].text.contains("artifact 7"));
        assert!(
            !transcript
                .entries
                .iter()
                .any(|entry| entry.text.contains("secret"))
        );
    }

    #[test]
    fn durable_tool_output_uses_the_live_summary_boundary() {
        let output = "private compiler detail\n".repeat(100);
        let mut transcript = Transcript::new(4096);
        transcript.record(&ChatMessage::tool_result("1", &output));

        assert_eq!(transcript.entries.len(), 1);
        assert_eq!(
            transcript.entries[0].text,
            format!("{} bytes", output.len())
        );
        assert!(
            !transcript.entries[0]
                .text
                .contains("private compiler detail")
        );

        transcript.record(&ChatMessage::tool_result("2", "wrote 6 bytes\n"));
        assert_eq!(transcript.entries[1].text, "wrote 6 bytes");
    }

    #[test]
    fn live_chunks_coalesce_and_stay_within_the_byte_limit() {
        let mut transcript = Transcript::new(12);
        for text in ["one", "two", "🦀tail"] {
            transcript.apply(&Event::ToolOutput {
                agent: 2,
                stream: ToolStream::Stdout,
                text: text.into(),
            });
        }

        assert_eq!(transcript.entries.len(), 1);
        assert_eq!(
            transcript.entries[0].source,
            Source::ToolOutput(2, ToolStream::Stdout)
        );
        assert!(transcript.entries[0].text.ends_with("🦀tail"));
        assert!(transcript.bytes() <= 12);
    }

    #[test]
    fn finished_tool_output_is_folded_into_its_summary() {
        let mut transcript = Transcript::new(1024);
        transcript.apply(&Event::ToolStart {
            agent: 2,
            detail: "build".into(),
        });
        transcript.apply(&Event::ToolOutput {
            agent: 2,
            stream: ToolStream::Stdout,
            text: "checking\n".into(),
        });
        transcript.apply(&Event::ToolOutput {
            agent: 2,
            stream: ToolStream::Stderr,
            text: "warning\n".into(),
        });
        transcript.apply(&Event::ToolEnd {
            agent: 2,
            outcome: crate::tools::ToolOutcome::Completed,
            detail: "18 bytes".into(),
            full: Some("checking\nwarning\n".into()),
        });

        assert_eq!(transcript.entries.len(), 2);
        assert_eq!(transcript.entries[0].text, "running build");
        assert_eq!(transcript.entries[1].text, "18 bytes");
        assert!(
            transcript
                .entries
                .iter()
                .all(|entry| !matches!(entry.source, Source::ToolOutput(..)))
        );
        assert_eq!(
            transcript.bytes(),
            transcript
                .entries
                .iter()
                .map(|entry| entry.text.len())
                .sum::<usize>()
        );
    }

    #[test]
    fn a_turn_boundary_prevents_later_chunks_from_merging() {
        let mut transcript = Transcript::new(100);
        transcript.apply(&Event::Token {
            agent: ROOT,
            text: "first".into(),
        });
        transcript.apply(&Event::TurnEnd {
            agent: ROOT,
            usage: crate::provider::UsageMeter::new(),
            ok: true,
        });
        transcript.apply(&Event::Token {
            agent: ROOT,
            text: "second".into(),
        });

        assert_eq!(transcript.entries.len(), 2);
        assert_eq!(transcript.entries[0].text, "first");
        assert_eq!(transcript.entries[1].text, "second");
    }

    #[test]
    fn tiny_limits_and_controls_cannot_escape_the_bound() {
        let mut transcript = Transcript::new(1);
        transcript.apply(&Event::Notice {
            agent: ROOT,
            text: "old".into(),
        });
        transcript.apply(&Event::Notice {
            agent: ROOT,
            text: "bad\x1b".into(),
        });

        assert_eq!(transcript.bytes(), 1);
        assert_eq!(transcript.entries()[0].text, "d");
    }
}
