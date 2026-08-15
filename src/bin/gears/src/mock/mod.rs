//! An in-process HTTP server that replays scripted responses, so gears'
//! tests exercise the real transport without talking to a model provider.
//!
//! **This module stays `std`-only.** Step 10 of the plan builds it into a
//! `mock-openrouter` binary that runs *inside* the Motor VM, which rules out
//! host-specific dependencies here.

pub mod scenario;
pub mod server;

pub use scenario::{
    PROVIDER_SCENARIOS, ProviderCase, SseCase, collect_sse, fragmented, plain_response,
    provider_conformance_corpus, provider_scenario, sse_corpus, sse_response,
    validate_provider_request,
};
pub use server::{MockServer, Piece, RecordedRequest, Route, Script};
