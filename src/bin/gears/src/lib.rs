//! Gears: a small extensible agent harness for Linux and Motor OS.

pub mod cancellation;
pub mod cli;
pub mod config;
pub mod hooks;
pub mod mock;
pub mod net;
pub mod platform;
pub mod process;
pub mod prompt;
#[cfg(test)]
mod property;
pub mod provider;
pub mod provider_choice;
pub mod run_lock;
pub mod runtime;
pub mod session;
pub mod shell_state;
pub mod state;
pub mod tools;
pub mod trace;
pub mod ui;
