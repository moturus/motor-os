//! Gears: a small extensible agent harness for Linux and Motor OS, with its
//! optional batteries (file tools, the check, memory and skills) in `batteries`.

pub mod batteries;
pub mod cancellation;
pub mod cli;
pub mod config;
pub mod directory;
pub mod hooks;
pub mod mock;
pub mod net;
pub mod permissions;
pub mod platform;
pub mod process;
pub mod prompt;
#[cfg(test)]
mod property;
pub mod provider;
pub mod provider_choice;
pub mod reset;
pub mod run_lock;
pub mod runtime;
pub mod session;
pub mod setup;
pub mod shell_state;
pub mod state;
pub mod tool_state;
pub mod tools;
pub mod trace;
pub mod ui;
