//! `gears-batteries history` and `status`: read-only views for the user.

use std::io::Write;

use serde_json::Value;

use crate::batteries::memory_options::{Command, Options};
use crate::batteries::paths::ToolContext;

pub fn run(args: &[String], mut output: impl Write) -> Result<(), String> {
    let options = Options::parse(args)?;
    let context = ToolContext::new(options.workspace, options.root, "cli".into(), None)?;
    let value = match options.command {
        Command::History { offset, limit } => {
            crate::batteries::memory_history::history(&context, offset, limit)?
        }
        Command::Status => crate::batteries::memory_history::status(&context),
    };
    write_json(&mut output, &value)
}

fn write_json(output: &mut impl Write, value: &Value) -> Result<(), String> {
    serde_json::to_writer_pretty(&mut *output, value).map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())
}
