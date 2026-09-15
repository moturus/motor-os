use std::{
    any::Any,
    fs::File,
    io::{self, BufRead, Cursor, Read, Write},
    path::PathBuf,
    sync::{Arc, mpsc},
};

use gix::tempfile::{AutoRemove, ContainingDirectory, Handle, handle::Writable};
use gix_transport::client::blocking_io::http::{
    self as transport_http, GetResponse, Http, PostBodyDataKind, PostResponse,
};

use crate::{
    cancellation::Cancellation,
    curl,
    http_request::{Client, MAX_UPLOAD_BYTES, Response},
    https_url::HttpsUrl,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct Adapter {
    client: Arc<Client>,
    staging: PathBuf,
    cancellation: Cancellation,
    redirected_base_url: Option<String>,
    may_follow_redirects: bool,
}

impl Adapter {
    pub fn new(
        ca_bundle: impl Into<PathBuf>,
        staging: impl Into<PathBuf>,
        response_limit: u64,
        cancellation: Cancellation,
    ) -> io::Result<Adapter> {
        let staging = staging.into();
        Ok(Adapter {
            client: Arc::new(Client::new(
                ca_bundle,
                staging.clone(),
                response_limit,
                cancellation.clone(),
            )?),
            staging,
            cancellation,
            redirected_base_url: None,
            may_follow_redirects: true,
        })
    }

    fn parse_request(
        &self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<(HttpsUrl, HttpsUrl, Vec<String>), transport_http::Error> {
        let url = HttpsUrl::parse(url).map_err(io_http_error)?;
        let base_url = HttpsUrl::parse(base_url).map_err(io_http_error)?;
        let headers = curl::collect_headers(headers).map_err(io_http_error)?;
        Ok((url, base_url, headers))
    }

    fn new_upload(&self) -> Result<(Upload, File, Arc<Handle<Writable>>), transport_http::Error> {
        self.cancellation.check().map_err(http_error)?;
        let mut guard = gix::tempfile::new(
            &self.staging,
            ContainingDirectory::Exists,
            AutoRemove::Tempfile,
        )
        .map_err(io_http_error)?;
        let writer = guard
            .with_mut(|file| file.as_file().try_clone())
            .map_err(io_http_error)?
            .map_err(io_http_error)?;
        let input = guard
            .with_mut(|file| file.as_file().try_clone())
            .map_err(io_http_error)?
            .map_err(io_http_error)?;
        let guard = Arc::new(guard);
        Ok((
            Upload {
                file: writer,
                written: 0,
                limit: MAX_UPLOAD_BYTES,
                cancellation: self.cancellation.clone(),
                _guard: guard.clone(),
            },
            input,
            guard,
        ))
    }
}

impl Http for Adapter {
    type Headers = Headers;
    type ResponseBody = Body;
    type PostBody = Upload;

    fn get(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<GetResponse<Self::Headers, Self::ResponseBody>, transport_http::Error> {
        let (url, base_url, headers) = self.parse_request(url, base_url, headers)?;
        let follow = std::mem::take(&mut self.may_follow_redirects);
        let response = self
            .client
            .request(url, base_url.clone(), &headers, None, follow)
            .map_err(http_error)?;
        if response.base_url != base_url {
            self.redirected_base_url = Some(response.base_url.as_str().to_owned());
        }
        let content_type = response.content_type.clone();
        Ok(GetResponse {
            headers: Headers::ready(content_type),
            body: Body::ready(response),
        })
    }

    fn post(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        _body: PostBodyDataKind,
    ) -> Result<
        PostResponse<Self::Headers, Self::ResponseBody, Self::PostBody>,
        transport_http::Error,
    > {
        self.may_follow_redirects = false;
        let (url, base_url, headers) = self.parse_request(url, base_url, headers)?;
        let (upload, input, guard) = self.new_upload()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let pending = Pending {
            client: self.client.clone(),
            url,
            base_url,
            headers,
            input,
            _guard: guard,
        };
        Ok(PostResponse {
            post_body: upload,
            headers: Headers::lazy(pending, sender),
            body: Body::lazy(receiver),
        })
    }

    fn configure(&mut self, _config: &dyn Any) -> Result<(), BoxError> {
        // Executable, TLS, proxy, redirect and timeout policy is fixed by construction.
        Ok(())
    }

    fn redirected_base_url(&self) -> Option<String> {
        self.redirected_base_url.clone()
    }
}

pub struct Upload {
    file: File,
    written: u64,
    limit: u64,
    cancellation: Cancellation,
    _guard: Arc<Handle<Writable>>,
}

impl Write for Upload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation.check().map_err(boxed_io)?;
        self.written
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| io::Error::other("Git HTTP upload exceeded its byte limit"))?;
        let count = self.file.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cancellation.check().map_err(boxed_io)?;
        self.file.flush()
    }
}

struct Pending {
    client: Arc<Client>,
    url: HttpsUrl,
    base_url: HttpsUrl,
    headers: Vec<String>,
    input: File,
    _guard: Arc<Handle<Writable>>,
}

impl Pending {
    fn run(self) -> crate::Result<Response> {
        self.client.request(
            self.url,
            self.base_url,
            &self.headers,
            Some(self.input),
            false,
        )
    }
}

pub struct Headers {
    bytes: Cursor<Vec<u8>>,
    pending: Option<Pending>,
    sender: Option<mpsc::SyncSender<Response>>,
    failed: bool,
}

impl Headers {
    fn ready(content_type: String) -> Headers {
        Headers {
            bytes: Cursor::new(header(content_type)),
            pending: None,
            sender: None,
            failed: false,
        }
    }

    fn lazy(pending: Pending, sender: mpsc::SyncSender<Response>) -> Headers {
        Headers {
            bytes: Cursor::new(Vec::new()),
            pending: Some(pending),
            sender: Some(sender),
            failed: false,
        }
    }

    fn start(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("Git HTTP request failed"));
        }
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let sender = self
            .sender
            .take()
            .ok_or_else(|| io::Error::other("Git HTTP response handoff is missing"))?;
        self.failed = true;
        let response = pending.run().map_err(boxed_io)?;
        self.bytes = Cursor::new(header(response.content_type.clone()));
        sender
            .send(response)
            .map_err(|_| io::Error::other("Git HTTP response body was dropped"))?;
        self.failed = false;
        Ok(())
    }
}

impl Read for Headers {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.start()?;
        self.bytes.read(bytes)
    }
}

impl BufRead for Headers {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.start()?;
        self.bytes.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.bytes.consume(amount);
    }
}

pub struct Body {
    response: Option<Response>,
    receiver: Option<mpsc::Receiver<Response>>,
}

impl Body {
    fn ready(response: Response) -> Body {
        Body {
            response: Some(response),
            receiver: None,
        }
    }

    fn lazy(receiver: mpsc::Receiver<Response>) -> Body {
        Body {
            response: None,
            receiver: Some(receiver),
        }
    }

    fn response(&mut self) -> io::Result<&mut Response> {
        if self.response.is_none() {
            let receiver = self
                .receiver
                .as_ref()
                .ok_or_else(|| io::Error::other("Git HTTP response was already taken"))?;
            self.response = Some(match receiver.try_recv() {
                Ok(response) => response,
                Err(mpsc::TryRecvError::Empty) => {
                    return Err(io::Error::other("Git HTTP request was not executed"));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("Git HTTP request failed or was dropped"));
                }
            });
            self.receiver = None;
        }
        Ok(self.response.as_mut().expect("response was initialized"))
    }
}

impl Read for Body {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.response()?.read(bytes)
    }
}

impl BufRead for Body {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.response()?.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        if let Some(response) = self.response.as_mut() {
            response.consume(amount);
        }
    }
}

fn header(content_type: String) -> Vec<u8> {
    format!("Content-Type: {content_type}\n").into_bytes()
}

fn io_http_error(error: io::Error) -> transport_http::Error {
    transport_http::Error::PostBody(error)
}

fn http_error(error: BoxError) -> transport_http::Error {
    match error.downcast::<io::Error>() {
        Ok(error) => io_http_error(*error),
        Err(source) => transport_http::Error::InitHttpClient { source },
    }
}

fn boxed_io(error: BoxError) -> io::Error {
    match error.downcast::<io::Error>() {
        Ok(error) => *error,
        Err(source) => io::Error::other(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://127.0.0.1:1/repo";
    const POST: &str = "https://127.0.0.1:1/repo/git-upload-pack";

    fn new_adapter(cancellation: Cancellation) -> Adapter {
        Adapter::new(
            "/unused-test-ca.pem",
            std::env::temp_dir(),
            16,
            cancellation,
        )
        .expect("adapter")
    }

    fn post(adapter: &mut Adapter) -> PostResponse<Headers, Body, Upload> {
        adapter
            .post(
                POST,
                BASE,
                [
                    "Content-Type: application/x-git-upload-pack-request",
                    "Accept: application/x-git-upload-pack-result",
                ],
                PostBodyDataKind::Unbounded,
            )
            .expect("lazy POST")
    }

    #[test]
    fn bounded_upload_and_failed_handoffs_are_errors() -> io::Result<()> {
        fn assert_send<T: Send>() {}
        assert_send::<Adapter>();
        assert_send::<Upload>();
        assert_send::<Headers>();
        assert_send::<Body>();
        let cancellation = Cancellation::new();
        let mut adapter = new_adapter(cancellation.clone());
        let mut response = post(&mut adapter);
        response.post_body.limit = 4;
        response.post_body.write_all(b"body")?;
        assert_eq!(response.post_body.file.metadata()?.len(), 4);
        assert!(response.post_body.write_all(b"x").is_err());
        cancellation.cancel();
        let error = response.post_body.write_all(b"x").expect_err("cancelled");
        assert!(crate::cancellation::was_cancelled(&error));
        drop(response.headers);
        assert!(
            response.body.read(&mut [0]).is_err(),
            "dropped request became EOF"
        );
        let path = Arc::get_mut(&mut response.post_body._guard)
            .expect("writer retains the only tempfile guard")
            .with_mut(|file| file.path().to_path_buf())?;
        assert!(path.is_file());
        drop(response.post_body);
        assert!(!path.exists());

        let cancellation = Cancellation::new();
        let mut adapter = new_adapter(cancellation.clone());
        let mut response = post(&mut adapter);
        drop(response.post_body);
        cancellation.cancel();
        let error = response
            .headers
            .read_line(&mut String::new())
            .expect_err("cancelled");
        assert!(crate::cancellation::was_cancelled(&error));
        assert!(
            response.body.read(&mut [0]).is_err(),
            "failed request became EOF"
        );

        let transport_cancelled = http_error(cancellation.check().expect_err("cancelled"));
        assert!(crate::cancellation::was_cancelled(&transport_cancelled));

        let mapped = http_error(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication failed",
        )));
        let transport_http::Error::PostBody(error) = mapped else {
            panic!("io::Error was not preserved");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }
}
