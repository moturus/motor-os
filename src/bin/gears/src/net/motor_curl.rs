//! The Motor OS backend of the HTTP seam — for now, an honest refusal.
//!
//! The real implementation drives the in-tree `src/bin/curl` crate as a
//! library, and needs the two curl-crate extensions the plan schedules (a
//! request writer and a head-first streaming receive). Until those land,
//! every request reports the transport as unsupported rather than being
//! absent: gears runs on Motor OS, and anything that needs the network says
//! why it cannot. Compiled on every platform so the host test suite can hold
//! it to that.

use super::{
    EgressPolicy, HttpClient, HttpRequest, HttpSink, NetError, ResponseHead, check_request,
};

pub const UNSUPPORTED: &str =
    "HTTPS is not supported on Motor OS yet (the curl-crate port, plan step 10)";

pub struct MotorCurl {
    policy: EgressPolicy,
}

impl MotorCurl {
    /// `Result` to mirror the host constructor, so `main` builds either
    /// backend with the same calls.
    pub fn new(policy: EgressPolicy) -> Result<MotorCurl, NetError> {
        Ok(MotorCurl { policy })
    }

    /// Registered for redaction exactly as the host transport registers a
    /// secret; there is nothing yet to send it to.
    pub fn with_secret(self, _env: &str, value: &str) -> MotorCurl {
        crate::trace::redact(value);
        self
    }
}

impl HttpClient for MotorCurl {
    fn execute(
        &self,
        req: &HttpRequest,
        _sink: &mut dyn HttpSink,
    ) -> Result<ResponseHead, NetError> {
        // The request is still validated and still passes egress: a caller
        // must not learn from this stub that a forbidden host was fine.
        check_request(req)?;
        self.policy.check(&req.url)?;
        Err(NetError::Transport(format!("unsupported: {UNSUPPORTED}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CollectSink, Url};

    #[test]
    fn every_request_is_checked_and_then_refused_as_unsupported() {
        let client =
            MotorCurl::new(EgressPolicy::new(&["openrouter.ai".to_string()])).unwrap();
        let mut sink = CollectSink::default();

        // Egress still answers first: a blocked host is blocked, not
        // unsupported.
        let req = HttpRequest::get(Url::parse("https://evil.test/x").unwrap());
        assert!(matches!(
            client.execute(&req, &mut sink),
            Err(NetError::Forbidden(_))
        ));

        let req = HttpRequest::get(Url::parse("https://openrouter.ai/api").unwrap());
        let err = client.execute(&req, &mut sink).unwrap_err();
        assert!(matches!(err, NetError::Transport(_)));
        assert!(err.to_string().contains("unsupported"), "{err}");
        assert!(sink.head.is_none(), "the stub delivered something");
    }
}
