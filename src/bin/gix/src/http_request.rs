use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
};

use gix::tempfile::{AutoRemove, ContainingDirectory, Handle, handle::Writable};

use crate::{
    cancellation::Cancellation,
    curl::{self, Metadata},
    curl_capture,
    https_url::HttpsUrl,
};

pub(crate) const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const DISCOVERY_SUFFIX: &str = "info/refs?service=git-upload-pack";
const RESULT_SUFFIX: &str = "git-upload-pack";
const DISCOVERY_TYPE: &str = "application/x-git-upload-pack-advertisement";
const RESULT_TYPE: &str = "application/x-git-upload-pack-result";

pub struct Client {
    ca_bundle: PathBuf,
    staging: PathBuf,
    response_limit: u64,
    cancellation: Cancellation,
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
            cancellation,
        })
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
        let endpoint = Endpoint::new(
            &url,
            &base_url,
            input_file.is_some(),
            follow_discovery_redirects,
        )?;
        let input_metadata = input_file.as_ref().map(File::metadata).transpose()?;
        if input_metadata
            .is_some_and(|metadata| !metadata.is_file() || metadata.len() > MAX_UPLOAD_BYTES)
        {
            return Err(input("Git HTTP upload must be a regular file of at most 8 MiB").into());
        }

        let mut current = url;
        for redirects in 0..=MAX_REDIRECTS {
            let (command, nonce) =
                curl::command(&current, &self.ca_bundle, headers, input_file.is_some())?;
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
}

#[derive(Debug)]
enum Decision {
    Complete(HttpsUrl),
    Redirect(HttpsUrl),
}

impl Endpoint {
    fn new(
        url: &HttpsUrl,
        base: &HttpsUrl,
        has_body: bool,
        follow_redirects: bool,
    ) -> io::Result<Endpoint> {
        let (suffix, content_type) = if has_body {
            (RESULT_SUFFIX, RESULT_TYPE)
        } else {
            (DISCOVERY_SUFFIX, DISCOVERY_TYPE)
        };
        if url.as_str() != append_url(base.as_str(), suffix) {
            return Err(input(
                "Git HTTP request is outside its upload-pack endpoint",
            ));
        }
        if has_body && follow_redirects {
            return Err(input("Git HTTP POST redirects are not allowed"));
        }
        Ok(Endpoint {
            suffix,
            content_type,
            may_redirect: follow_redirects,
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
        check_status(metadata.status, diagnostic)?;
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
        .ok_or_else(|| data("Git HTTP redirect changed its upload-pack suffix"))?;
    HttpsUrl::parse(base)
}

fn check_status(status: u16, diagnostic: &[u8]) -> io::Result<()> {
    if status == 200 {
        return Ok(());
    }
    let message = format!(
        "Git HTTP returned status {status}{}",
        diagnostic_suffix(diagnostic)
    );
    Err(io::Error::new(
        if status == 401 {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::Other
        },
        message,
    ))
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
            let url = append_parsed(&base, DISCOVERY_SUFFIX)?;
            let endpoint = Endpoint::new(&url, &base, false, true)?;
            let Decision::Complete(actual) = inspect(
                endpoint,
                &url,
                &base,
                metadata(200, &url, None, DISCOVERY_TYPE),
            )?
            else {
                panic!("expected completion");
            };
            assert_eq!(actual, base);
        }

        let base = HttpsUrl::parse("https://example.com/repo")?;
        let discovery = append_parsed(&base, DISCOVERY_SUFFIX)?;
        let get = Endpoint::new(&discovery, &base, false, true)?;
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
            metadata(200, &next, None, DISCOVERY_TYPE),
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

        let post = append_parsed(&base, RESULT_SUFFIX)?;
        let result = Endpoint::new(&post, &base, true, false)?;
        let other = HttpsUrl::parse("https://example.com/else")?;
        assert!(Endpoint::new(&other, &base, false, true).is_err());
        assert!(
            inspect(
                result,
                &post,
                &base,
                metadata(200, &other, None, RESULT_TYPE)
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
            metadata(401, &post, None, RESULT_TYPE),
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
}
