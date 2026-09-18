use std::{
    io,
    path::{Path, PathBuf},
};

use gix::bstr::ByteSlice;

use crate::{cancellation::Cancellation, http::Adapter, https_url::HttpsUrl, ssh};

const MAX_RESPONSE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone)]
pub struct Policy {
    ca_bundle: PathBuf,
    cancellation: Cancellation,
}

impl Policy {
    /// Only explicit command-line configuration may replace the system CA bundle.
    pub fn new(overrides: &[&str], cancellation: &Cancellation) -> crate::Result<Self> {
        #[cfg(target_os = "motor")]
        let mut ca_bundle = PathBuf::from("/system/cfg/ssl/ca-certificates.crt");
        #[cfg(not(target_os = "motor"))]
        let mut ca_bundle = PathBuf::from("/etc/ssl/certs/ca-certificates.crt");
        for setting in overrides {
            let (key, value) = setting
                .split_once('=')
                .map_or((*setting, None), |(k, v)| (k, Some(v)));
            let key = gix::config::KeyRef::parse_unvalidated(key.trim().as_bytes().as_bstr())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid configuration key")
                })?;
            if key.section_name.eq_ignore_ascii_case("http")
                && key.subsection_name.is_none()
                && key.value_name.eq_ignore_ascii_case("sslCAInfo")
            {
                let value = value.filter(|v| !v.is_empty()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "http.sslCAInfo requires a CA bundle path",
                    )
                })?;
                ca_bundle = PathBuf::from(value);
            }
        }
        Ok(Self {
            ca_bundle,
            cancellation: cancellation.clone(),
        })
    }

    pub fn transport(
        &self,
        url: gix::url::Url,
        staging: &Path,
        registrar: &ssh::Registrar,
    ) -> crate::Result<Box<dyn gix_transport::client::blocking_io::Transport + Send>> {
        self.cancellation.check()?;
        if url.scheme == gix::url::Scheme::Ssh {
            return Ok(Box::new(
                ssh::Prepared::new(url)?.transport(registrar.clone()),
            ));
        }
        validate_url(&url)?;
        let adapter = Adapter::new(
            &self.ca_bundle,
            staging,
            MAX_RESPONSE_BYTES,
            self.cancellation.clone(),
        )?;
        Ok(Box::new(
            gix_transport::client::blocking_io::http::Transport::new_http(
                adapter,
                url,
                gix_transport::Protocol::V2,
                false,
            ),
        ))
    }
}

pub fn validate_url(url: &gix::url::Url) -> crate::Result {
    match &url.scheme {
        gix::url::Scheme::Ssh => ssh::Prepared::new(url.clone()).map(|_| ()),
        _ => {
            HttpsUrl::parse(url.to_bstring().to_str()?)?;
            Ok(())
        }
    }
}

/// Reap SSH sessions before classifying the acquisition result or cancellation.
pub fn finish<T>(
    operation: ssh::Operation,
    transfer: crate::Result<T>,
    cancellation: &Cancellation,
) -> crate::Result<T> {
    let disposition = if transfer.is_ok() {
        ssh::Finish::Complete
    } else {
        ssh::Finish::Abort
    };
    complete(transfer, operation.finish(disposition))
        .map_err(|error| cancellation.normalize_error(error))
}

fn complete<T>(transfer: crate::Result<T>, completion: crate::Result) -> crate::Result<T> {
    match (transfer, completion) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(protocol), Err(completion)) => {
            Err(Failure::with_secondary("SSH completion also failed", protocol, completion).into())
        }
    }
}

pub fn check_outcome(outcome: &gix::remote::fetch::Outcome) -> crate::Result {
    use gix::remote::fetch::{Status, refs::update::Mode};
    let (Status::Change { update_refs, .. } | Status::NoPackReceived { update_refs, .. }) =
        &outcome.status;
    for (index, update) in update_refs.updates.iter().enumerate() {
        match update.mode {
            Mode::NoChangeNeeded
            | Mode::FastForward
            | Mode::Forced
            | Mode::New
            | Mode::ImplicitTagNotSentByRemote => {}
            _ => {
                let name = outcome
                    .ref_map
                    .mappings
                    .get(index)
                    .and_then(|mapping| mapping.local.as_ref())
                    .map(|name| name.to_str_lossy().escape_debug().to_string())
                    .unwrap_or_else(|| "(unmapped reference)".to_owned());
                return Err(io::Error::other(format!(
                    "fetch update '{name}' was {}; other references may already have changed",
                    update.mode
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// Preserve the original error (including cancellation) while describing possible partial writes.
#[derive(Debug)]
pub struct Failure {
    message: String,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl Failure {
    pub fn new(message: String, source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self { message, source }
    }

    /// Keep the primary source and include every cause of a secondary failure.
    pub fn with_secondary(
        label: &str,
        source: Box<dyn std::error::Error + Send + Sync>,
        secondary: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        let mut message = format!("{label}: {secondary}");
        let mut cause = secondary.source();
        while let Some(error) = cause {
            message.push_str(": ");
            message.push_str(&error.to_string());
            cause = error.source();
        }
        Self { message, source }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.message)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_preserves_both_failures_and_cancellation_classification() {
        let protocol = || Err::<(), _>(io::Error::other("protocol failed").into());
        let completion = || Err(io::Error::other("child failed").into());
        assert_eq!(complete(Ok(7), Ok(())).unwrap(), 7);
        assert_eq!(
            complete(protocol(), Ok(())).unwrap_err().to_string(),
            "protocol failed"
        );
        assert_eq!(
            complete(Ok(()), completion()).unwrap_err().to_string(),
            "child failed"
        );
        let secondary = Failure::new(
            "child cleanup failed".into(),
            io::Error::other("pipe failed").into(),
        );
        let nested = complete(protocol(), Err(secondary.into())).unwrap_err();
        assert!(
            nested
                .to_string()
                .contains("child cleanup failed: pipe failed")
        );
        let combined = complete(protocol(), completion()).unwrap_err();
        assert!(combined.to_string().contains("child failed"));
        assert_eq!(combined.source().unwrap().to_string(), "protocol failed");
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let combined = cancellation.normalize_error(combined);
        assert!(crate::cancellation::was_cancelled(combined.as_ref()));
        assert_eq!(
            combined.source().unwrap().source().unwrap().to_string(),
            "protocol failed"
        );
    }

    #[test]
    fn only_explicit_ca_override_and_supported_acquisition_urls() -> crate::Result {
        let cancellation = Cancellation::new();
        let policy = Policy::new(
            &[
                "http.sslCAInfo=first",
                "http.sslVerify=false",
                "HTTP.sslcainfo=last",
            ],
            &cancellation,
        )?;
        assert_eq!(policy.ca_bundle, Path::new("last"));
        assert!(Policy::new(&["http.sslCAInfo"], &cancellation).is_err());
        assert!(Policy::new(&["http.sslCAInfo="], &cancellation).is_err());
        for value in [
            "http://example.test/repo",
            "https://user@example.test/repo",
            "file:///repo",
        ] {
            assert!(validate_url(&gix::url::parse(value.as_bytes().as_bstr())?).is_err());
        }
        for value in ["https://example.test/repo", "ssh://motor@example.test/repo"] {
            validate_url(&gix::url::parse(value.as_bytes().as_bstr())?)?;
        }
        Ok(())
    }
}
