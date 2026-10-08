//! Versioned event output for unattended one-shot runs.

use std::io::Write;

use serde_json::{Value, json};

use crate::process::Stream;
use crate::provider::{Role, UsageMeter};
use crate::runtime::{Event, Observer, Runtime, Unattended};

pub const VERSION: u32 = 1;

pub fn run(runtime: &mut Runtime, prompt: String, writer: impl Write) -> Result<(), String> {
    let mut output = Renderer {
        writer,
        usage: UsageMeter::new(),
    };
    let summary = runtime.summary();
    let mut result = (|| {
        output.record(json!({
            "type": "session", "version": VERSION,
            "session_id": summary.id, "path": summary.path,
            "session_format_version": runtime.session().format_version(),
        }))?;
        runtime.set_interactive(false)?;
        if let Some(hint) = runtime.hint() {
            output.event(Event::Hint(Some(hint.to_string())))?;
        }
        for notice in runtime.take_startup_notices() {
            output.event(Event::Notice(notice))?;
        }
        runtime.turn(prompt, &mut Unattended, &mut output)
    })();
    for notice in runtime.close() {
        if let Err(error) = output.event(Event::Notice(notice))
            && result.is_ok()
        {
            result = Err(error);
        }
    }
    let answer = if result.is_ok() {
        runtime
            .session()
            .context_messages()?
            .iter()
            .rev()
            .find(|message| message.role == Role::Assistant)
            .map(|message| message.text_content())
    } else {
        None
    };
    output.record(json!({
        "type": "final", "success": result.is_ok(), "answer": answer,
        "error": result.as_ref().err().map(|error| crate::trace::scrub(error)),
        "usage": usage_value(&output.usage),
        "session_usage": usage_value(runtime.usage()),
    }))?;
    result
}

struct Renderer<W> {
    writer: W,
    usage: UsageMeter,
}

impl<W: Write> Renderer<W> {
    fn record(&mut self, value: Value) -> Result<(), String> {
        serde_json::to_writer(&mut self.writer, &value)
            .map_err(|error| format!("JSONL output: {error}"))?;
        self.writer
            .write_all(b"\n")
            .and_then(|()| self.writer.flush())
            .map_err(|error| format!("JSONL output: {error}"))
    }
}

fn usage_value(usage: &UsageMeter) -> Value {
    json!({
        "completions": usage.completions,
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "total_tokens": usage.total_tokens(),
        "cost_usd": usage.cost_usd(),
        "cost_is_partial": usage.cost_is_partial(),
    })
}

impl<W: Write> Observer for Renderer<W> {
    fn event(&mut self, event: Event) -> Result<(), String> {
        let record = match event {
            Event::Text(text) => json!({"type": "text", "text": text}),
            Event::Reasoning(text) => json!({"type": "reasoning", "text": text}),
            Event::ToolStart {
                call_id,
                name,
                detail,
            } => json!({"type": "tool_start", "call_id": call_id, "name": name, "detail": detail}),
            Event::ToolOutput { name, stream, text } => json!({
                "type": "tool_output", "name": name, "text": text,
                "stream": match stream { Stream::Stdout => "stdout", Stream::Stderr => "stderr" },
            }),
            Event::ToolEnd {
                call_id,
                name,
                content,
                is_error,
                outcome,
            } => json!({
                "type": "tool_result", "call_id": call_id, "name": name,
                "content": content, "is_error": is_error, "outcome": outcome,
            }),
            Event::Permission(permission) => json!({
                "type": "permission", "tool": permission.tool,
                "detail": permission.detail, "workspace": permission.workspace,
            }),
            Event::Notice(text) => json!({"type": "notice", "text": text}),
            Event::Hint(hint) => json!({"type": "hint", "text": hint}),
            Event::Usage { request, total } => {
                self.usage.add(&request);
                json!({"type": "usage", "request": request, "total": usage_value(&total)})
            }
            Event::ModelChanged(model) => json!({"type": "model", "model": model}),
            Event::SessionChanged(session) => json!({
                "type": "session_changed", "session_id": session.id, "path": session.path,
            }),
            Event::TurnEnd {
                status,
                tool_rounds,
                last_entry_id,
            } => json!({
                "type": "turn_end", "status": status,
                "tool_rounds": tool_rounds, "last_entry_id": last_entry_id,
            }),
        };
        self.record(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Usage;

    #[test]
    fn records_escape_multiline_output_and_keep_unknown_cost_distinct() {
        let mut bytes = Vec::new();
        let mut renderer = Renderer {
            writer: &mut bytes,
            usage: UsageMeter::new(),
        };
        renderer
            .event(Event::Text("one\ntwo \"quoted\"".into()))
            .unwrap();
        let request = Usage {
            prompt_tokens: 5,
            completion_tokens: 2,
            ..Usage::default()
        };
        let mut total = UsageMeter::new();
        total.add(&request);
        renderer.event(Event::Usage { request, total }).unwrap();
        assert_eq!(renderer.usage.total_tokens(), 7);
        let records = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["text"], "one\ntwo \"quoted\"");
        assert_eq!(records[1]["total"]["total_tokens"], 7);
        assert!(records[1]["total"]["cost_usd"].is_null());
        assert_eq!(records[1]["total"]["cost_is_partial"], false);
    }

    #[test]
    fn output_failure_aborts_the_observer() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut renderer = Renderer {
            writer: Closed,
            usage: UsageMeter::new(),
        };
        assert!(
            renderer
                .event(Event::Text("answer".into()))
                .unwrap_err()
                .contains("JSONL output")
        );
    }
}
