//! The host backend: an `HttpClient` driving the system `curl` binary
//! through the shared [`CurlTransport`] engine. It exists so gears is
//! developed and tested on Linux against the same seam — and now the same
//! command line — that `MotorCurl` uses on Motor OS.

use std::process::Command;

use super::curl::CurlTransport;
use super::{EgressPolicy, HttpClient, HttpRequest, HttpSink, NetError, ResponseHead};

/// `--variable` and `--expand-header` are what keep the API key out of the
/// argument vector, and they arrived in curl 8.3.0 (2023).
const MIN_CURL: (u32, u32) = (8, 3);

pub struct HostCurl {
    transport: CurlTransport,
}

impl HostCurl {
    pub fn new(policy: EgressPolicy) -> Result<HostCurl, NetError> {
        HostCurl::with_program("curl", policy)
    }

    pub fn with_program(program: &str, policy: EgressPolicy) -> Result<HostCurl, NetError> {
        let (major, minor) = curl_version(program)?;
        if (major, minor) < MIN_CURL {
            return Err(NetError::Transport(format!(
                "{program} is version {major}.{minor}; gears needs {}.{} or newer for \
                 --expand-header, which keeps the API key out of the command line",
                MIN_CURL.0, MIN_CURL.1
            )));
        }
        Ok(HostCurl {
            transport: CurlTransport::new(program, policy),
        })
    }

    /// Supply the value for a secret header's environment variable. The
    /// value is registered for redaction, so it cannot appear in the trace.
    pub fn with_secret(mut self, env: &str, value: &str) -> HostCurl {
        self.transport.add_secret(env, value);
        self
    }

    pub fn with_verbosity(mut self, level: u8) -> HostCurl {
        // Upstream curl's verbose mode prints header values, including the
        // bearer key. Keep gears' own safe transport diagnostics on hosts.
        self.transport.set_verbosity(level, false);
        self
    }
}

impl HttpClient for HostCurl {
    fn execute(
        &self,
        req: &HttpRequest,
        sink: &mut dyn HttpSink,
    ) -> Result<ResponseHead, NetError> {
        self.transport.execute(req, sink)
    }
}

fn curl_version(program: &str) -> Result<(u32, u32), NetError> {
    let out = Command::new(program)
        .arg("--version")
        .output()
        .map_err(|e| NetError::Transport(format!("cannot run {program}: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "curl 8.18.0 (x86_64-pc-linux-gnu) libcurl/8.18.0 ..."
    let version = text
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| NetError::Transport(format!("cannot read {program} --version")))?;
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok());
    let minor = parts.next().and_then(|p| p.parse().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(NetError::Transport(format!(
            "cannot parse {program} version {version:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_curl_is_new_enough() {
        let (major, minor) = curl_version("curl").unwrap();
        assert!(
            (major, minor) >= MIN_CURL,
            "this host's curl is {major}.{minor}; gears needs {}.{}",
            MIN_CURL.0,
            MIN_CURL.1
        );
        assert!(matches!(
            curl_version("gears-no-such-program"),
            Err(NetError::Transport(_))
        ));
    }
}
