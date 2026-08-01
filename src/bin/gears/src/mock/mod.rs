//! An in-process HTTP server that replays scripted responses, so gears'
//! tests exercise the real transport without talking to a model provider.
//!
//! **This module stays `std`-only.** Step 10 of the plan builds it into a
//! `mock-openrouter` binary that runs *inside* the Motor VM, which rules out
//! host-specific dependencies here.

pub mod scenario;
pub mod server;

pub use scenario::{SseCase, collect_sse, sse_corpus};
pub use server::{MockServer, Piece, RecordedRequest, Script};
