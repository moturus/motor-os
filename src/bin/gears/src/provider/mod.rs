//! The model-provider seam.
//!
//! gears targets the OpenAI-compatible chat-completions *wire dialect*, not a
//! single vendor: one client with a configurable base URL, model id and key,
//! plus a small quirk table for the places endpoints differ. OpenRouter is
//! the blessed default and the only endpoint validated against a real key;
//! other compatible endpoints are config-only and untested.

mod assembler;
pub mod key;
pub mod openai_compat;
pub mod types;
pub mod usage;
mod wire;

use crate::net::NetError;

pub use key::ApiKey;
pub use openai_compat::{Endpoint, OpenAiCompat, Quirks, UsageStyle};
pub use types::{
    Completion, ContentBlock, FinishReason, Message, Request, Role, StreamEvent, ToolCall,
    ToolSpec, Usage,
};
pub use usage::UsageMeter;

/// The environment variable the key reaches the transport in. The name stays
/// `OPENROUTER_API_KEY` even when the endpoint is something else (plan
/// decision 5): it is one name for one secret, not a vendor claim.
pub const KEY_ENV: &str = "OPENROUTER_API_KEY";

/// Why a completion failed. The variants are what the agent layer reacts to:
/// a key problem, a spend problem and a truncated stream call for different
/// responses, and none of them is retried automatically (plan decision 7).
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderError {
    /// 401/403: the key is missing, rejected, or not allowed this model.
    Auth(String),
    /// 402: out of credit.
    Credits(String),
    /// 429, carrying `Retry-After` in seconds when the endpoint sent one.
    RateLimited {
        retry_after: Option<u64>,
        detail: String,
    },
    /// 5xx, or the endpoint reporting the upstream model as overloaded.
    Unavailable(String),
    /// Any other failure the endpoint reported. `status` is absent when it
    /// came from inside a stream, which carries no status of its own.
    Api { status: Option<u16>, detail: String },
    /// The stream ended before the model said it was finished.
    Truncated(String),
    /// Valid HTTP, invalid dialect.
    Protocol(String),
    /// The transport itself failed.
    Net(NetError),
    /// The caller cancelled — a `^C` during a turn, not a failure.
    Aborted(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Auth(d) => write!(f, "authentication failed: {d}"),
            ProviderError::Credits(d) => write!(f, "out of credit: {d}"),
            ProviderError::RateLimited {
                retry_after: Some(seconds),
                detail,
            } => write!(f, "rate limited (retry after {seconds}s): {detail}"),
            ProviderError::RateLimited { detail, .. } => write!(f, "rate limited: {detail}"),
            ProviderError::Unavailable(d) => write!(f, "model unavailable: {d}"),
            ProviderError::Api {
                status: Some(status),
                detail,
            } => write!(f, "provider error {status}: {detail}"),
            ProviderError::Api { detail, .. } => write!(f, "provider error: {detail}"),
            ProviderError::Truncated(d) => write!(f, "the response was cut short: {d}"),
            ProviderError::Protocol(d) => write!(f, "unexpected response: {d}"),
            ProviderError::Net(e) => write!(f, "{e}"),
            ProviderError::Aborted(d) => write!(f, "cancelled: {d}"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl ProviderError {
    /// Map a response status to a cause. `detail` is the endpoint's own
    /// explanation of the failure, which is the part a user can act on.
    pub fn from_status(status: u16, retry_after: Option<u64>, detail: String) -> ProviderError {
        match status {
            401 | 403 => ProviderError::Auth(detail),
            402 => ProviderError::Credits(detail),
            429 => ProviderError::RateLimited {
                retry_after,
                detail,
            },
            500..=599 => ProviderError::Unavailable(detail),
            _ => ProviderError::Api {
                status: Some(status),
                detail,
            },
        }
    }
}

impl From<NetError> for ProviderError {
    fn from(e: NetError) -> ProviderError {
        match e {
            // A cancelled turn is not a network failure, whichever layer
            // noticed it first.
            NetError::Aborted(detail) => ProviderError::Aborted(detail),
            other => ProviderError::Net(other),
        }
    }
}

/// Where streamed deltas go while a completion is being assembled, so the UI
/// renders tokens as they arrive. Returning `Err` cancels the request: the
/// error travels down to the transport, which drops the connection.
pub trait EventSink {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()>;
}

/// Drops every delta; the completion is still assembled and returned.
pub struct Discard;

impl EventSink for Discard {
    fn on_event(&mut self, _event: StreamEvent) -> std::io::Result<()> {
        Ok(())
    }
}

pub trait Provider: Send + Sync {
    /// Run one completion to the end, streaming deltas to `sink`.
    fn complete(
        &self,
        req: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError>;
}

/// So that a provider can be chosen at run time and handed to a thread.
impl<P: Provider + ?Sized> Provider for Box<P> {
    fn complete(
        &self,
        req: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        (**self).complete(req, sink)
    }
}

/// And so that several agents can share one. A completion takes `&self` and
/// carries its own connection — the host backend spawns a curl of its own per
/// request — so sharing one provider is not sharing a conversation.
impl<P: Provider + ?Sized> Provider for std::sync::Arc<P> {
    fn complete(
        &self,
        req: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        (**self).complete(req, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_happened() {
        assert_eq!(
            ProviderError::RateLimited {
                retry_after: Some(7),
                detail: "slow down".to_string(),
            }
            .to_string(),
            "rate limited (retry after 7s): slow down"
        );
        assert_eq!(
            ProviderError::Api {
                status: Some(418),
                detail: "teapot".to_string(),
            }
            .to_string(),
            "provider error 418: teapot"
        );
        // A network error keeps its own wording rather than being wrapped.
        assert_eq!(
            ProviderError::from(NetError::Timeout("no data for 90s".to_string())).to_string(),
            "timed out: no data for 90s"
        );
    }

    #[test]
    fn statuses_map_to_causes() {
        let detail = || "detail".to_string();
        for (status, expected) in [
            (401, ProviderError::Auth(detail())),
            (403, ProviderError::Auth(detail())),
            (402, ProviderError::Credits(detail())),
            (503, ProviderError::Unavailable(detail())),
            (
                400,
                ProviderError::Api {
                    status: Some(400),
                    detail: detail(),
                },
            ),
        ] {
            assert_eq!(ProviderError::from_status(status, None, detail()), expected);
        }
        assert_eq!(
            ProviderError::from_status(429, Some(3), detail()),
            ProviderError::RateLimited {
                retry_after: Some(3),
                detail: detail(),
            }
        );
    }

    #[test]
    fn a_transport_abort_stays_an_abort() {
        assert!(matches!(
            ProviderError::from(NetError::Aborted("^C".to_string())),
            ProviderError::Aborted(_)
        ));
    }
}
