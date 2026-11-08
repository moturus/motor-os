use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
    sync::OnceLock,
};

use gix::tempfile::{AutoRemove, ContainingDirectory, Handle, handle::Writable};
use gix_transport::Service;

use crate::{
    cancellation::Cancellation,
    curl::{self, Metadata},
    curl_capture,
    https_url::HttpsUrl,
    prompt::Credential,
};

const MAX_REDIRECTS: usize = 5;

/// The two smart-HTTP endpoints of one Git service and its request-body bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Endpoints {
    discovery: &'static str,
    advertisement: &'static str,
    request: &'static str,
    result: &'static str,
    upload_limit: u64,
}

impl Endpoints {
    const fn of(service: Service) -> Endpoints {
        match service {
            Service::UploadPack => Endpoints {
                discovery: "info/refs?service=git-upload-pack",
                advertisement: "application/x-git-upload-pack-advertisement",
                request: "git-upload-pack",
                result: "application/x-git-upload-pack-result",
                upload_limit: 8 * 1024 * 1024,
            },
            Service::ReceivePack => Endpoints {
                discovery: "info/refs?service=git-receive-pack",
                advertisement: "application/x-git-receive-pack-advertisement",
                request: "git-receive-pack",
                result: "application/x-git-receive-pack-result",
                upload_limit: crate::push_protocol::MAX_REQUEST_BYTES,
            },
        }
    }
}

/// Runs the requests of exactly one Git service; other services' URLs are refused.
pub struct Client {
    ca_bundle: PathBuf,
    staging: PathBuf,
    response_limit: u64,
    endpoints: Endpoints,
    credential: OnceLock<Credential>,
    cancellation: Cancellation,
}

/// A 401 from the server, which a local `PermissionDenied` never is.
#[derive(Debug)]
struct Unauthorized(String);

impl fmt::Display for Unauthorized {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

impl Error for Unauthorized {}

/// The server's 401, as `is_unauthorized` recognizes it.
pub(crate) fn unauthorized(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, Unauthorized(message))
}

/// Whether `error` is the server's 401 itself.
pub fn is_unauthorized(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .is_some_and(|inner| inner.is::<Unauthorized>())
}

pub struct Response {
    reader: BufReader<File>,
    _guard: Handle<Writable>,
    pub content_type: String,
    pub base_url: HttpsUrl,
}

impl Read for Response {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reader.read(bytes)
    }
}

impl BufRead for Response {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.reader.consume(amount);
    }
}

impl Client {
    pub fn new(
        ca_bundle: impl Into<PathBuf>,
        staging: impl Into<PathBuf>,
        response_limit: u64,
        service: Service,
        cancellation: Cancellation,
    ) -> io::Result<Client> {
        if response_limit == 0 {
            return Err(input("Git HTTP response limit must be nonzero"));
        }
        let staging = staging.into();
        if !staging.is_dir() {
            return Err(input("Git HTTP staging directory does not exist"));
        }
        Ok(Client {
            ca_bundle: ca_bundle.into(),
            staging,
            response_limit,
            endpoints: Endpoints::of(service),
            credential: OnceLock::new(),
            cancellation,
        })
    }

    /// The largest request body this client's service may send.
    pub fn upload_limit(&self) -> u64 {
        self.endpoints.upload_limit
    }

    pub fn has_credential(&self) -> bool {
        self.credential.get().is_some()
    }

    /// Send `credential` with every later request; a client takes only one.
    pub fn set_credential(&self, credential: Credential) -> io::Result<()> {
        self.credential
            .set(credential)
            .map_err(|_| io::Error::other("Git HTTP credentials were already given"))
    }

    pub fn request(
        &self,
        url: HttpsUrl,
        base_url: HttpsUrl,
        headers: &[String],
        mut input_file: Option<File>,
        follow_discovery_redirects: bool,
    ) -> crate::Result<Response> {
        self.cancellation.check()?;
        let endpoint = Endpoint {
            authenticated: self.has_credential(),
            ..Endpoint::new(
                self.endpoints,
                &url,
                &base_url,
                input_file.is_some(),
                follow_discovery_redirects,
            )?
        };
        let input_metadata = input_file.as_ref().map(File::metadata).transpose()?;
        let limit = self.upload_limit();
        if input_metadata.is_some_and(|metadata| !metadata.is_file() || metadata.len() > limit) {
            return Err(input(format!(
                "Git HTTP upload must be a regular file within the {limit}-byte limit"
            ))
            .into());
        }

        let mut current = url;
        for redirects in 0..=MAX_REDIRECTS {
            let (command, nonce) = curl::command(
                &current,
                &self.ca_bundle,
                headers,
                input_file.is_some(),
                self.credential.get(),
            )?;
            let mut guard = gix::tempfile::new(
                &self.staging,
                ContainingDirectory::Exists,
                AutoRemove::Tempfile,
            )?;
            let output = guard.with_mut(|file| file.as_file().try_clone())??;
            let captured = curl_capture::capture(
                command,
                output,
                input_file.take(),
                self.response_limit,
                &self.cancellation,
            )?;
            let parsed = curl::parse_metadata(&captured.stderr, &nonce, captured.body_size);
            if !captured.status.success() {
                let diagnostic = parsed
                    .map(|(diagnostic, _)| diagnostic)
                    .unwrap_or(captured.stderr);
                return Err(io::Error::other(format!(
                    "curl exited with {}{}",
                    captured.status,
                    diagnostic_suffix(&diagnostic)
                ))
                .into());
            }
            let (diagnostic, metadata) = parsed?;
            match endpoint.inspect(&current, &base_url, metadata, redirects, &diagnostic)? {
                Decision::Complete(base_url) => {
                    return Ok(Response {
                        reader: BufReader::new(captured.response),
                        _guard: guard,
                        content_type: endpoint.content_type.to_owned(),
                        base_url,
                    });
                }
                Decision::Redirect(next) => current = next,
            }
        }
        unreachable!("redirect limit is checked before continuing")
    }
}

#[derive(Clone, Copy)]
struct Endpoint {
    suffix: &'static str,
    content_type: &'static str,
    may_redirect: bool,
    authenticated: bool,
}

#[derive(Debug)]
enum Decision {
    Complete(HttpsUrl),
    Redirect(HttpsUrl),
}

impl Endpoint {
    fn new(
        endpoints: Endpoints,
        url: &HttpsUrl,
        base: &HttpsUrl,
        has_body: bool,
        follow_redirects: bool,
    ) -> io::Result<Endpoint> {
        let (suffix, content_type) = if has_body {
            (endpoints.request, endpoints.result)
        } else {
            (endpoints.discovery, endpoints.advertisement)
        };
        if url.as_str() != append_url(base.as_str(), suffix) {
            return Err(input("Git HTTP request is outside its service's endpoints"));
        }
        if has_body && follow_redirects {
            return Err(input("Git HTTP POST redirects are not allowed"));
        }
        Ok(Endpoint {
            suffix,
            content_type,
            may_redirect: follow_redirects,
            authenticated: false,
        })
    }

    fn inspect(
        self,
        current: &HttpsUrl,
        original_base: &HttpsUrl,
        metadata: Metadata,
        redirects: usize,
        diagnostic: &[u8],
    ) -> io::Result<Decision> {
        if metadata.effective_url != *current {
            return Err(data("curl reported an unexpected Git effective URL"));
        }
        if matches!(metadata.status, 301 | 302 | 303 | 307 | 308) {
            if !self.may_redirect {
                return Err(data(format!(
                    "Git HTTP redirect status {} is not allowed for this request",
                    metadata.status
                )));
            }
            if redirects == MAX_REDIRECTS {
                return Err(data("Git HTTP response exceeded the 5-redirect limit"));
            }
            let next = metadata
                .redirect_url
                .ok_or_else(|| data("Git HTTP redirect omitted its destination"))?;
            let next = original_base.same_origin_redirect(next.as_str())?;
            redirected_base(&next, self.suffix)?;
            return Ok(Decision::Redirect(next));
        }
        if metadata.redirect_url.is_some() {
            return Err(data(
                "curl reported a redirect URL for a non-redirect response",
            ));
        }
        check_status(metadata.status, diagnostic, self.authenticated)?;
        if metadata.content_type != self.content_type {
            return Err(data(format!(
                "Git HTTP expected content type `{}`, got `{}`",
                self.content_type,
                metadata.content_type.escape_debug()
            )));
        }
        if current.as_str() == append_url(original_base.as_str(), self.suffix) {
            Ok(Decision::Complete(original_base.clone()))
        } else {
            Ok(Decision::Complete(redirected_base(current, self.suffix)?))
        }
    }
}

fn append_url(base: &str, suffix: &str) -> String {
    format!(
        "{base}{}{suffix}",
        if base.ends_with('/') { "" } else { "/" }
    )
}

#[cfg(test)]
fn append_parsed(base: &HttpsUrl, suffix: &str) -> io::Result<HttpsUrl> {
    HttpsUrl::parse(&append_url(base.as_str(), suffix))
}

fn redirected_base(url: &HttpsUrl, suffix: &str) -> io::Result<HttpsUrl> {
    let base = url
        .as_str()
        .strip_suffix(suffix)
        .filter(|base| base.ends_with('/'))
        .ok_or_else(|| data("Git HTTP redirect changed its service suffix"))?;
    HttpsUrl::parse(base)
}

fn check_status(status: u16, diagnostic: &[u8], authenticated: bool) -> io::Result<()> {
    if status == 200 {
        return Ok(());
    }
    let refused = if status == 401 && authenticated {
        ": the server refused the credentials"
    } else {
        ""
    };
    let message = format!(
        "Git HTTP returned status {status}{refused}{}",
        diagnostic_suffix(diagnostic)
    );
    Err(if status == 401 {
        unauthorized(message)
    } else {
        io::Error::other(message)
    })
}

fn diagnostic_suffix(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::new()
    } else {
        format!(": {}", String::from_utf8_lossy(bytes).escape_debug())
    }
}

fn input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPLOAD: Endpoints = Endpoints::of(Service::UploadPack);
    const RECEIVE: Endpoints = Endpoints::of(Service::ReceivePack);

    fn metadata(status: u16, current: &HttpsUrl, next: Option<&str>, kind: &str) -> Metadata {
        Metadata {
            status,
            effective_url: current.clone(),
            redirect_url: next.map(HttpsUrl::parse).transpose().expect("valid URL"),
            content_type: kind.into(),
            size: 0,
        }
    }

    fn inspect(
        endpoint: Endpoint,
        current: &HttpsUrl,
        base: &HttpsUrl,
        meta: Metadata,
    ) -> io::Result<Decision> {
        endpoint.inspect(current, base, meta, 0, b"\x1bdenied\n")
    }

    #[test]
    fn upload_pack_endpoint_and_response_policy() -> io::Result<()> {
        for value in ["https://EXAMPLE.com:443/repo", "https://example.com/repo/"] {
            let base = HttpsUrl::parse(value)?;
            let url = append_parsed(&base, UPLOAD.discovery)?;
            let endpoint = Endpoint::new(UPLOAD, &url, &base, false, true)?;
            let Decision::Complete(actual) = inspect(
                endpoint,
                &url,
                &base,
                metadata(200, &url, None, UPLOAD.advertisement),
            )?
            else {
                panic!("expected completion");
            };
            assert_eq!(actual, base);
        }

        let base = HttpsUrl::parse("https://example.com/repo")?;
        let discovery = append_parsed(&base, UPLOAD.discovery)?;
        let get = Endpoint::new(UPLOAD, &discovery, &base, false, true)?;
        let moved = "https://example.com/moved/repo/info/refs?service=git-upload-pack";
        let Decision::Redirect(next) = inspect(
            get,
            &discovery,
            &base,
            metadata(302, &discovery, Some(moved), ""),
        )?
        else {
            panic!("expected redirect");
        };
        let Decision::Complete(actual) = inspect(
            get,
            &next,
            &base,
            metadata(200, &next, None, UPLOAD.advertisement),
        )?
        else {
            panic!("expected completion");
        };
        assert_eq!(actual.as_str(), "https://example.com/moved/repo/");
        assert!(
            get.inspect(
                &discovery,
                &base,
                metadata(302, &discovery, Some(moved), ""),
                MAX_REDIRECTS,
                &[],
            )
            .is_err()
        );

        let post = append_parsed(&base, UPLOAD.request)?;
        let result = Endpoint::new(UPLOAD, &post, &base, true, false)?;
        let other = HttpsUrl::parse("https://example.com/else")?;
        assert!(Endpoint::new(UPLOAD, &other, &base, false, true).is_err());
        assert!(
            inspect(
                result,
                &post,
                &base,
                metadata(200, &other, None, UPLOAD.result)
            )
            .is_err()
        );
        let bad_type = inspect(
            result,
            &post,
            &base,
            metadata(200, &post, None, "text/\u{85}plain"),
        )
        .expect_err("content type");
        assert!(bad_type.to_string().contains(r"\u{85}"));
        let denied = inspect(
            result,
            &post,
            &base,
            metadata(401, &post, None, UPLOAD.result),
        )
        .expect_err("401");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert!(denied.to_string().contains(r"\u{1b}denied\n"));
        assert!(
            inspect(
                result,
                &post,
                &base,
                metadata(307, &post, Some(post.as_str()), "")
            )
            .is_err()
        );
        for next in [
            "https://other.example/repo/info/refs?service=git-upload-pack",
            "https://example.com/moved/info/refs?service=git-receive-pack",
        ] {
            assert!(
                inspect(
                    get,
                    &discovery,
                    &base,
                    metadata(302, &discovery, Some(next), "")
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn only_a_server_401_asks_for_credentials() -> io::Result<()> {
        let base = HttpsUrl::parse("https://example.com/repo")?;
        let url = append_parsed(&base, RECEIVE.discovery)?;
        let get = Endpoint::new(RECEIVE, &url, &base, false, true)?;
        let anonymous = inspect(get, &url, &base, metadata(401, &url, None, "")).unwrap_err();
        assert!(is_unauthorized(&anonymous));
        assert!(!anonymous.to_string().contains("refused"));
        let sent = Endpoint {
            authenticated: true,
            ..get
        };
        let refused = inspect(sent, &url, &base, metadata(401, &url, None, "")).unwrap_err();
        assert!(is_unauthorized(&refused));
        assert!(
            refused
                .to_string()
                .contains("the server refused the credentials")
        );
        let forbidden = inspect(get, &url, &base, metadata(403, &url, None, "")).unwrap_err();
        assert!(!is_unauthorized(&forbidden));
        assert!(!is_unauthorized(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        Ok(())
    }

    #[test]
    fn receive_pack_endpoints_and_cross_service_refusal() -> crate::Result {
        let base = HttpsUrl::parse("https://example.com/repo")?;
        let discovery = append_parsed(&base, RECEIVE.discovery)?;
        let post = append_parsed(&base, RECEIVE.request)?;
        let get = Endpoint::new(RECEIVE, &discovery, &base, false, true)?;
        let advertisement = metadata(200, &discovery, None, RECEIVE.advertisement);
        assert!(matches!(
            inspect(get, &discovery, &base, advertisement)?,
            Decision::Complete(actual) if actual == base
        ));
        let result = Endpoint::new(RECEIVE, &post, &base, true, false)?;
        inspect(
            result,
            &post,
            &base,
            metadata(200, &post, None, RECEIVE.result),
        )?;
        let wrong = metadata(200, &post, None, UPLOAD.result);
        assert!(inspect(result, &post, &base, wrong).is_err());
        let moved = "https://example.com/moved/repo/info/refs?service=git-receive-pack";
        assert!(matches!(
            inspect(get, &discovery, &base, metadata(302, &discovery, Some(moved), ""))?,
            Decision::Redirect(next) if next.as_str() == moved
        ));
        let switched = "https://example.com/moved/repo/info/refs?service=git-upload-pack";
        let switched = metadata(302, &discovery, Some(switched), "");
        assert!(inspect(get, &discovery, &base, switched).is_err());
        for (endpoints, suffix, has_body) in [
            (RECEIVE, UPLOAD.discovery, false),
            (RECEIVE, UPLOAD.request, true),
            (UPLOAD, RECEIVE.discovery, false),
            (UPLOAD, RECEIVE.request, true),
        ] {
            let url = append_parsed(&base, suffix)?;
            assert!(Endpoint::new(endpoints, &url, &base, has_body, false).is_err());
        }

        // Each service's body limit holds before curl starts.
        let staging = std::env::temp_dir();
        for (service, limit) in [
            (Service::UploadPack, 8 << 20),
            (Service::ReceivePack, (128 << 20) + 65_524),
        ] {
            let client = Client::new("/unused-ca.pem", &staging, 16, service, Cancellation::new())?;
            assert_eq!(client.upload_limit(), limit);
            let mut body =
                gix::tempfile::new(&staging, ContainingDirectory::Exists, AutoRemove::Tempfile)?;
            let file = body.with_mut(|file| file.as_file().try_clone())??;
            file.set_len(limit + 1)?;
            let endpoints = Endpoints::of(service);
            let url = append_parsed(&base, endpoints.request)?;
            let error = client
                .request(url, base.clone(), &[], Some(file), false)
                .err()
                .expect("oversized upload");
            assert!(error.to_string().contains(&format!("{limit}-byte limit")));
        }
        Ok(())
    }
}
