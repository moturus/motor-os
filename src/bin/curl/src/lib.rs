mod error;
mod http;
mod options;
mod url;
mod write_out;

pub use error::{CurlError, CurlResult};
pub use http::{Response, receive_response, write_request};
pub use options::{Action, Options};
pub use url::HttpsUrl;
pub use write_out::{TransferInfo, write_out};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn help() -> &'static str {
    "Usage: curl [OPTIONS] --url <HTTPS-URL>\n\
\n\
Options:\n\
      --disable                       Disable curl configuration files\n\
      --silent                        Suppress progress output\n\
      --show-error                    Show errors when used with --silent\n\
      --globoff                       Disable URL globbing\n\
      --http1.1                       Use HTTP/1.1\n\
      --proto =https                  Permit HTTPS only\n\
      --noproxy *                     Disable proxies\n\
      --disallow-username-in-url      Reject URL user information\n\
      --tlsv1.2                       Require TLS 1.2 or newer\n\
      --tls-max 1.3                   Permit TLS 1.3 at most\n\
      --connect-timeout <SECONDS>     Bound connection establishment\n\
      --max-time <SECONDS>            Bound the complete transfer\n\
      --speed-limit <BYTES>           Set the low-speed byte threshold\n\
      --speed-time <SECONDS>          Set the low-speed interval\n\
      --user-agent <VALUE>            Set the User-Agent header\n\
      --header <HEADER>               Add a request header\n\
      --output -                      Write the response body to stdout\n\
      --write-out <FORMAT>            Write transfer metadata\n\
      --cacert <ABSOLUTE-PATH>        Load trust roots from a PEM file\n\
      --url <HTTPS-URL>               Set the request URL\n\
      --help                          Print help\n\
      --version                       Print version\n"
}

pub fn version() -> String {
    format!("curl {VERSION} (Motor OS) rustls\nProtocols: https\n")
}
