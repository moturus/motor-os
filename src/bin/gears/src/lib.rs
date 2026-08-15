//! gears — an agentic coding harness. See `proposal.md` (design) and
//! `step-by-step-plan.md` (build order) in the crate root.

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
