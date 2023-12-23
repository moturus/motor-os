#![allow(unreachable_code, clippy::needless_return)]

use crate::io::{decode_response, encode_request};
use crate::model::{
    HeaderName, HeaderValue, InvalidHeader, Method, Request, Response, Status, Url,
};
use crate::utils::{invalid_data_error, invalid_input_error};
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(all(feature = "rustls", feature = "webpki-roots"))]
use rustls::OwnedTrustAnchor;
#[cfg(feature = "rustls")]
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName, StreamOwned};
#[cfg(feature = "rustls-native-certs")]
use rustls_native_certs::load_native_certs;
use std::io::{BufReader, BufWriter, Error, ErrorKind, Result};
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "rustls")]
use std::sync::Arc;
#[cfg(any(feature = "native-tls", feature = "rustls"))]
use std::sync::OnceLock;
use std::time::Duration;
#[cfg(feature = "webpki-roots")]
use webpki_roots::TLS_SERVER_ROOTS;

/// An HTTP client.
///
/// It aims at following the basic concepts of the [Web Fetch standard](https://fetch.spec.whatwg.org/) without the bits specific to web browsers (context, CORS...).
///
/// HTTPS is supported behind the disabled by default `native-tls` feature (to use the current system native implementation), or `rustls-webpki` feature (to use [Rustls](https://github.com/rustls/rustls) with [Common CA Database](https://www.ccadb.org/)),  or `rustls-native` feature (to use [Rustls](https://github.com/rustls/rustls) with host certificates).
///
/// If the `flate2` feature is enabled, the client will automatically decode `gzip` and `deflate` content-encodings.
///
/// The client does not follow redirections by default. Use [`Client::with_redirection_limit`] to set a limit to the number of consecutive redirections the server should follow.
///
/// Missing: HSTS support, authentication and keep alive.
///
/// ```
/// use oxhttp::Client;
/// use oxhttp::model::{Request, Method, Status, HeaderName};
/// use std::io::Read;
///
/// let client = Client::new();
/// let response = client.request(Request::builder(Method::GET, "http://example.com".parse()?).build())?;
/// assert_eq!(response.status(), Status::OK);
/// assert_eq!(response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(), b"text/html; charset=UTF-8");
/// let body = response.into_body().to_string()?;
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(Default)]
pub struct Client {
    timeout: Option<Duration>,
    user_agent: Option<HeaderValue>,
    redirection_limit: usize,
}

impl Client {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the global timeout value (applies to both read, write and connection).
    #[inline]
    pub fn with_global_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the default value for the [`User-Agent`](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#field.user-agent) header.
    #[inline]
    pub fn with_user_agent(
        mut self,
        user_agent: impl Into<String>,
    ) -> std::result::Result<Self, InvalidHeader> {
        self.user_agent = Some(HeaderValue::try_from(user_agent.into())?);
        Ok(self)
    }

    /// Sets the number of time a redirection should be followed.
    /// By default the redirections are not followed (limit = 0).
    #[inline]
    pub fn with_redirection_limit(mut self, limit: usize) -> Self {
        self.redirection_limit = limit;
        self
    }

    pub fn request(&self, mut request: Request) -> Result<Response> {
        // Loops the number of allowed redirections + 1
        for _ in 0..(self.redirection_limit + 1) {
            let previous_method = request.method().clone();
            let response = self.single_request(&mut request)?;
            let Some(location) = response.header(&HeaderName::LOCATION) else {
                return Ok(response);
            };
            let new_method = match response.status() {
                Status::MOVED_PERMANENTLY | Status::FOUND | Status::SEE_OTHER => {
                    if previous_method == Method::HEAD {
                        Method::HEAD
                    } else {
                        Method::GET
                    }
                }
                Status::TEMPORARY_REDIRECT | Status::PERMANENT_REDIRECT
                    if previous_method.is_safe() =>
                {
                    previous_method
                }
                _ => return Ok(response),
            };
            let location = location.to_str().map_err(invalid_data_error)?;
            let new_url = request.url().join(location).map_err(|e| {
                invalid_data_error(format!(
                    "Invalid URL in Location header raising error {e}: {location}"
                ))
            })?;
            let mut request_builder = Request::builder(new_method, new_url);
            for (header_name, header_value) in request.headers() {
                request_builder
                    .headers_mut()
                    .set(header_name.clone(), header_value.clone());
            }
            request = request_builder.build();
        }
        Err(Error::new(
            ErrorKind::Other,
            format!(
                "The server requested too many redirects ({}). The latest redirection target is {}",
                self.redirection_limit + 1,
                request.url()
            ),
        ))
    }

    fn single_request(&self, request: &mut Request) -> Result<Response> {
        // Additional headers
        {
            let headers = request.headers_mut();
            headers.set(
                HeaderName::CONNECTION,
                HeaderValue::new_unchecked("close".as_bytes()),
            );
            if let Some(user_agent) = &self.user_agent {
                if !headers.contains(&HeaderName::USER_AGENT) {
                    headers.set(HeaderName::USER_AGENT, user_agent.clone())
                }
            }
            if cfg!(feature = "flate2")
                && !headers.contains(&HeaderName::ACCEPT_ENCODING)
                && !headers.contains(&HeaderName::RANGE)
            {
                headers.set(
                    HeaderName::ACCEPT_ENCODING,
                    HeaderValue::new_unchecked("gzip,deflate".as_bytes()),
                );
            }
        }

        #[cfg(any(feature = "native-tls", feature = "rustls"))]
        let host = request
            .url()
            .host_str()
            .ok_or_else(|| invalid_input_error("No host provided"))?;

        match request.url().scheme() {
            "http" => {
                let addresses = get_and_validate_socket_addresses(request.url(), 80)?;
                let stream = self.connect(&addresses)?;
                let stream = encode_request(request, BufWriter::new(stream))?
                    .into_inner()
                    .map_err(|e| e.into_error())?;
                decode_response(BufReader::new(stream))
            }
            "https" => {
                #[cfg(feature = "native-tls")]
                {
                    static TLS_CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();

                    let addresses = get_and_validate_socket_addresses(request.url(), 443)?;
                    let stream = self.connect(&addresses)?;
                    let stream = TLS_CONNECTOR
                        .get_or_init(|| match TlsConnector::new() {
                            Ok(connector) => connector,
                            Err(e) => panic!("Error while loading TLS configuration: {}", e), // TODO: use get_or_try_init
                        })
                        .connect(host, stream)
                        .map_err(|e| Error::new(ErrorKind::Other, e))?;
                    let stream = encode_request(request, BufWriter::new(stream))?
                        .into_inner()
                        .map_err(|e| e.into_error())?;
                    return decode_response(BufReader::new(stream));
                }
                #[cfg(feature = "rustls")]
                {
                    static RUSTLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

                    let rustls_config = RUSTLS_CONFIG.get_or_init(|| {
                        let mut root_store = RootCertStore::empty();

                        #[cfg(feature = "rustls-native-certs")]
                        {
                            match load_native_certs() {
                                Ok(certs) => {
                                    for cert in certs {
                                        root_store.add_parsable_certificates(&[cert.0]);
                                    }
                                }
                                Err(e) => panic!("Error loading TLS certificates: {}", e),
                            }
                        }
                        #[cfg(feature = "webpki-roots")]
                        {
                            root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(
                                |trust_anchor| {
                                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                                        trust_anchor.subject,
                                        trust_anchor.spki,
                                        trust_anchor.name_constraints,
                                    )
                                },
                            ));
                        }
                        #[cfg(not(any(
                            feature = "rustls-native-certs",
                            feature = "webpki-roots"
                        )))]
                        compile_error!(
            "rustls-native-certs or webpki-roots must be installed to use OxHTTP with Rustls"
        );

                        Arc::new(
                            ClientConfig::builder()
                                .with_safe_defaults()
                                .with_root_certificates(root_store)
                                .with_no_client_auth(),
                        )
                    });
                    let addresses = get_and_validate_socket_addresses(request.url(), 443)?;
                    let dns_name = ServerName::try_from(host).map_err(invalid_input_error)?;
                    let connection = ClientConnection::new(Arc::clone(rustls_config), dns_name)
                        .map_err(|e| Error::new(ErrorKind::Other, e))?;
                    let stream = StreamOwned::new(connection, self.connect(&addresses)?);
                    let stream = encode_request(request, BufWriter::new(stream))?
                        .into_inner()
                        .map_err(|e| e.into_error())?;
                    return decode_response(BufReader::new(stream));
                }
                #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
                return Err(invalid_input_error("HTTPS is not supported by the client. You should enable the `native-tls` or `rustls` feature of the `oxhttp` crate"));
            }
            _ => Err(invalid_input_error(format!(
                "Not supported URL scheme: {}",
                request.url().scheme()
            ))),
        }
    }

    fn connect(&self, addresses: &[SocketAddr]) -> Result<TcpStream> {
        let stream = if let Some(timeout) = self.timeout {
            Self::connect_timeout(addresses, timeout)
        } else {
            TcpStream::connect(addresses)
        }?;
        stream.set_read_timeout(self.timeout)?;
        stream.set_write_timeout(self.timeout)?;
        Ok(stream)
    }

    fn connect_timeout(addresses: &[SocketAddr], timeout: Duration) -> Result<TcpStream> {
        let mut error = Error::new(
            ErrorKind::InvalidInput,
            "Not able to resolve the provide addresses",
        );
        for address in addresses {
            match TcpStream::connect_timeout(address, timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) => error = e,
            }
        }
        Err(error)
    }
}

// Bad ports https://fetch.spec.whatwg.org/#bad-port
// Should be sorted
const BAD_PORTS: [u16; 80] = [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102,
    103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465,
    512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993,
    995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669,
    6697, 10080,
];

fn get_and_validate_socket_addresses(url: &Url, default_port: u16) -> Result<Vec<SocketAddr>> {
    let addresses = url.socket_addrs(|| Some(default_port))?;
    for address in &addresses {
        if BAD_PORTS.binary_search(&address.port()).is_ok() {
            return Err(invalid_input_error(format!(
                "The port {} is not allowed for HTTP(S) because it is dedicated to an other use",
                address.port()
            )));
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Method, Status};

    #[test]
    fn test_http_get_ok() -> Result<()> {
        let client = Client::new();
        let response = client.request(
            Request::builder(Method::GET, "http://example.com".parse().unwrap()).build(),
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(),
            b"text/html; charset=UTF-8"
        );
        let body = response.into_body().to_string()?;
        assert!(body.contains("<html"));
        Ok(())
    }

    #[test]
    fn test_http_get_ok_with_user_agent_and_timeout() -> Result<()> {
        let client = Client::new()
            .with_user_agent("OxHTTP/1.0")
            .unwrap()
            .with_global_timeout(Duration::from_secs(5));
        let response = client.request(
            Request::builder(Method::GET, "http://example.com".parse().unwrap()).build(),
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(),
            b"text/html; charset=UTF-8"
        );
        Ok(())
    }

    #[test]
    fn test_http_get_ok_explicit_port() -> Result<()> {
        let client = Client::new();
        let response = client.request(
            Request::builder(Method::GET, "http://example.com:80".parse().unwrap()).build(),
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(),
            b"text/html; charset=UTF-8"
        );
        Ok(())
    }

    #[test]
    fn test_http_wrong_port() {
        let client = Client::new();
        assert!(client
            .request(
                Request::builder(Method::GET, "http://example.com:22".parse().unwrap()).build(),
            )
            .is_err());
    }

    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    #[test]
    fn test_https_get_ok() -> Result<()> {
        let client = Client::new();
        let response = client.request(
            Request::builder(Method::GET, "https://example.com".parse().unwrap()).build(),
        )?;
        assert_eq!(response.status(), Status::OK);
        assert_eq!(
            response.header(&HeaderName::CONTENT_TYPE).unwrap().as_ref(),
            b"text/html; charset=UTF-8"
        );
        Ok(())
    }

    #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
    #[test]
    fn test_https_get_err() {
        let client = Client::new();
        assert!(client
            .request(Request::builder(Method::GET, "https://example.com".parse().unwrap()).build())
            .is_err());
    }

    #[test]
    fn test_http_get_not_found() -> Result<()> {
        let client = Client::new();
        let response = client.request(
            Request::builder(
                Method::GET,
                "http://example.com/not_existing".parse().unwrap(),
            )
            .build(),
        )?;
        assert_eq!(response.status(), Status::NOT_FOUND);
        Ok(())
    }

    #[test]
    fn test_file_get_error() {
        let client = Client::new();
        assert!(client
            .request(
                Request::builder(
                    Method::GET,
                    "file://example.com/not_existing".parse().unwrap(),
                )
                .build(),
            )
            .is_err());
    }

    #[cfg(any(feature = "native-tls", feature = "rustls"))]
    #[test]
    fn test_redirection() -> Result<()> {
        let client = Client::new().with_redirection_limit(5);
        let response = client.request(
            Request::builder(Method::GET, "http://wikipedia.org".parse().unwrap()).build(),
        )?;
        assert_eq!(response.status(), Status::OK);
        Ok(())
    }
}
