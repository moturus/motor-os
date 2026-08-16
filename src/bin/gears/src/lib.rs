//! gears — an agentic coding harness. See `README.md` (user guide) and
//! `proposal.md` (design and roadmap) in the crate root.

pub mod agent;
pub mod cli;
pub mod config;
pub mod mock;
pub mod net;
pub mod platform;
#[cfg(test)]
pub(crate) mod property;
pub mod provider;
pub mod state;
pub mod tools;
pub mod trace;
pub mod ui;
