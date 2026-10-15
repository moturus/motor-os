//! Explicit user acceptance saved through Gears' existing hook context entries.

use crate::provider::Message;
use serde_json::{Value, json};

use crate::batteries::Event;

pub const ACCEPTED_CONTEXT: &str =
    "[User command /accept]\nThe user accepted the current task's result.";

pub fn specification() -> Value {
    json!({"name": "accept", "help": "Accept the current task's result."})
}

pub fn execute(event: &Event) -> Result<Value, String> {
    if event.payload["name"] != "accept" {
        return Err("unknown batteries command".into());
    }
    let argument = event.payload["argument"]
        .as_str()
        .ok_or("invalid /accept arguments")?;
    if !argument.trim().is_empty() {
        return Err("/accept takes no arguments".into());
    }
    Ok(json!({"context": Message::user(ACCEPTED_CONTEXT), "notice": "Task accepted."}))
}
