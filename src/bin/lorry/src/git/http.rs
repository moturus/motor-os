use std::any::Any;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};

use gix_features::io::pipe;
use gix_transport::client::blocking_io::http::{
    self, GetResponse, Http, PostBodyDataKind, PostResponse,
};

use crate::curl::{Client, GitMetadata, git_request};
use crate::redirect::{HttpsUrl, TrustPolicy};

const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

pub(super) struct Remote {
    request: Option<mpsc::SyncSender<Request>>,
    response: mpsc::Receiver<Response>,
    worker: Option<std::thread::JoinHandle<()>>,
    redirected_base_url: Arc<Mutex<Option<String>>>,
    may_follow_redirects: bool,
}

impl Remote {
    pub(super) fn new(
        client: Client,
        trust: Arc<Mutex<TrustPolicy>>,
        staging: PathBuf,
        max_response_bytes: u64,
        verbose: bool,
    ) -> io::Result<Self> {
        fs::create_dir(&staging)?;
        let (request_tx, request_rx) = mpsc::sync_channel(0);
        let (response_tx, response_rx) = mpsc::sync_channel(0);
        let redirected_base_url = Arc::new(Mutex::new(None));
        let worker_redirect = redirected_base_url.clone();
        let worker = std::thread::spawn(move || {
            worker(
                request_rx,
                response_tx,
                client,
                trust,
                staging,
                max_response_bytes,
                verbose,
                worker_redirect,
            );
        });
        Ok(Self {
            request: Some(request_tx),
            response: response_rx,
            worker: Some(worker),
            redirected_base_url,
            may_follow_redirects: true,
        })
    }

    fn make_request(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        upload: Option<PostBodyDataKind>,
    ) -> Result<PostResponse<pipe::Reader, pipe::Reader, pipe::Writer>, http::Error> {
        let headers = validated_headers(headers)?;
        let request = Request {
            url: url.to_owned(),
            base_url: base_url.to_owned(),
            headers,
            upload,
            follow_redirects: self.may_follow_redirects,
        };
        self.may_follow_redirects = false;
        self.request
            .as_ref()
            .ok_or_else(stopped)?
            .send(request)
            .map_err(|_| stopped())?;
        let response = self.response.recv().map_err(|_| stopped())?;
        Ok(PostResponse {
            post_body: response.upload,
            headers: response.headers,
            body: response.body,
        })
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        drop(self.request.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Http for Remote {
    type Headers = pipe::Reader;
    type ResponseBody = pipe::Reader;
    type PostBody = pipe::Writer;

    fn get(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<GetResponse<Self::Headers, Self::ResponseBody>, http::Error> {
        self.make_request(url, base_url, headers, None)
            .map(Into::into)
    }

    fn post(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        body: PostBodyDataKind,
    ) -> Result<PostResponse<Self::Headers, Self::ResponseBody, Self::PostBody>, http::Error> {
        self.make_request(url, base_url, headers, Some(body))
    }

    fn configure(
        &mut self,
        config: &dyn Any,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let Some(options) = config.downcast_ref::<http::Options>() else {
            return Ok(());
        };
        if !options.extra_headers.is_empty()
            || options.proxy.is_some()
            || options.no_proxy.is_some()
            || options.proxy_authenticate.is_some()
            || options.low_speed_limit_bytes_per_second != 0
            || options.low_speed_time_seconds != 0
            || options.connect_timeout.is_some()
            || options.ssl_ca_info.is_some()
            || options.ssl_version.is_some()
            || !options.ssl_verify
            || options.http_version.is_some()
            || options.backend.is_some()
        {
            return Err(io::Error::other(
                "Lorry's Git HTTP transport rejects ambient HTTP configuration",
            )
            .into());
        }
        Ok(())
    }

    fn redirected_base_url(&self) -> Option<String> {
        self.redirected_base_url
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

struct Request {
    url: String,
    base_url: String,
    headers: Vec<String>,
    upload: Option<PostBodyDataKind>,
    follow_redirects: bool,
}

struct Response {
    headers: pipe::Reader,
    body: pipe::Reader,
    upload: pipe::Writer,
}

#[allow(clippy::too_many_arguments)]
fn worker(
    requests: mpsc::Receiver<Request>,
    responses: mpsc::SyncSender<Response>,
    client: Client,
    trust: Arc<Mutex<TrustPolicy>>,
    staging: PathBuf,
    max_response_bytes: u64,
    verbose: bool,
    redirected_base_url: Arc<Mutex<Option<String>>>,
) {
    let response_path = staging.join("response");
    for request in requests {
        let (upload_tx, mut upload_rx) = pipe::unidirectional(0);
        let (mut headers_tx, headers_rx) = pipe::unidirectional(0);
        let (mut body_tx, body_rx) = pipe::unidirectional(0);
        if responses
            .send(Response {
                headers: headers_rx,
                body: body_rx,
                upload: upload_tx,
            })
            .is_err()
        {
            break;
        }
        let body = request.upload.map(|_| {
            let mut body = Vec::new();
            upload_rx
                .by_ref()
                .take(MAX_UPLOAD_BYTES + 1)
                .read_to_end(&mut body)
                .map(|_| body)
        });
        let result = match body.transpose() {
            Ok(Some(body)) if body.len() as u64 > MAX_UPLOAD_BYTES => Err(io::Error::other(
                format!("Git HTTP upload exceeded the {MAX_UPLOAD_BYTES}-byte limit"),
            )),
            Ok(body) => perform(
                &client,
                &trust,
                &response_path,
                max_response_bytes,
                verbose,
                request,
                body,
                &redirected_base_url,
            ),
            Err(error) => Err(error),
        };
        match result {
            Ok(metadata) => {
                let _ = writeln!(headers_tx, "Content-Type: {}", metadata.content_type);
                drop(headers_tx);
                if let Ok(mut file) = File::open(&response_path) {
                    let _ = io::copy(&mut file, &mut body_tx);
                }
            }
            Err(error) => {
                let _ = headers_tx.channel.send(Err(error));
            }
        }
        let _ = fs::remove_file(&response_path);
    }
    let _ = fs::remove_dir(&staging);
}

#[allow(clippy::too_many_arguments)]
fn perform(
    client: &Client,
    trust: &Arc<Mutex<TrustPolicy>>,
    response_path: &PathBuf,
    max_response_bytes: u64,
    verbose: bool,
    request: Request,
    body: Option<Vec<u8>>,
    redirected_base_url: &Arc<Mutex<Option<String>>>,
) -> io::Result<GitMetadata> {
    let tail = request
        .url
        .strip_prefix(&request.base_url)
        .filter(|tail| tail.starts_with('/'))
        .ok_or_else(|| io::Error::other("Git HTTP request URL is outside its base URL"))?;
    let mut current = HttpsUrl::parse(&request.url).map_err(as_io)?;
    let mut seen = BTreeSet::from([current.request_url.clone()]);
    for redirects in 0..=MAX_REDIRECTS {
        let destination = File::create(response_path)?;
        let (diagnostic, metadata) = git_request(
            &client.executable,
            &current.request_url,
            client.ca_bundle.as_deref(),
            destination,
            max_response_bytes,
            &request.headers,
            body.clone(),
        )
        .map_err(as_io)?;
        if verbose && !diagnostic.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&diagnostic));
        }
        if metadata.effective_url != current.request_url {
            return Err(io::Error::other(
                "curl reported an unexpected Git effective URL",
            ));
        }
        if !matches!(metadata.status, 301 | 302 | 303 | 307 | 308) {
            check_status(metadata.status)?;
            let new_base = current
                .request_url
                .strip_suffix(tail)
                .ok_or_else(|| io::Error::other("Git redirect changed the request suffix"))?;
            if new_base != request.base_url {
                *redirected_base_url
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(new_base.to_owned());
            }
            return Ok(metadata);
        }
        if !request.follow_redirects || (body.is_some() && !matches!(metadata.status, 307 | 308)) {
            return Err(io::Error::other(format!(
                "Git HTTP redirect status {} is not allowed for this request",
                metadata.status
            )));
        }
        if redirects == MAX_REDIRECTS {
            return Err(io::Error::other(
                "Git HTTP response exceeded the 5-redirect limit",
            ));
        }
        let next = metadata
            .redirect_url
            .as_deref()
            .ok_or_else(|| io::Error::other("Git HTTP redirect omitted its destination"))?;
        let next = HttpsUrl::parse(next).map_err(as_io)?;
        if !next.request_url.ends_with(tail) || !seen.insert(next.request_url.clone()) {
            return Err(io::Error::other(
                "Git HTTP redirect changed its suffix or formed a loop",
            ));
        }
        trust
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .authorize(&current, &next)
            .map_err(as_io)?;
        current = next;
    }
    unreachable!()
}

fn check_status(status: u16) -> io::Result<()> {
    match status {
        200 => Ok(()),
        401 => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Git HTTP authentication failed",
        )),
        500..=599 => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("Git HTTP returned status {status}"),
        )),
        _ => Err(io::Error::other(format!(
            "Git HTTP returned status {status}"
        ))),
    }
}

fn validated_headers(
    headers: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, http::Error> {
    let mut result = Vec::new();
    for header in headers {
        let header = header.as_ref();
        let Some((name, value)) = header.split_once(':') else {
            return Err(http::Error::Detail {
                description: "Git HTTP supplied a malformed request header".into(),
            });
        };
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "accept" | "content-type" | "git-protocol" | "user-agent"
        ) || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
        {
            return Err(http::Error::Detail {
                description: format!("Git HTTP supplied unsupported header `{name}`"),
            });
        }
        result.push(header.to_owned());
    }
    Ok(result)
}

fn stopped() -> http::Error {
    http::Error::Detail {
        description: "Lorry's Git HTTP worker stopped".into(),
    }
}

fn as_io(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_git_smart_http_header_surface() {
        let headers = validated_headers([
            "Accept: application/x-git-upload-pack-result",
            "Content-Type: application/x-git-upload-pack-request",
            "Git-Protocol: version=2",
            "User-Agent: git/2",
        ])
        .unwrap();
        assert_eq!(headers.len(), 4);

        for header in [
            "Authorization: secret",
            "Cookie: secret",
            "Accept",
            "Accept: value\rmalicious: yes",
        ] {
            assert!(validated_headers([header]).is_err(), "accepted `{header}`");
        }
    }

    #[test]
    fn maps_git_http_statuses_without_accepting_other_success_codes() {
        assert!(check_status(200).is_ok());
        assert_eq!(
            check_status(401).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            check_status(503).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(check_status(204).is_err());
        assert!(check_status(302).is_err());
    }
}
